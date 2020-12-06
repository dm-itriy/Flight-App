package flightapp;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.transform.Result;

/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;

  // Session status
  private boolean session_login;
  private String session_user;

  // Session variables
  private List<Itinerary> itineraries;

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;

  // For check dangling
  private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
  private PreparedStatement tranCountStatement;

  // Prepared Statements
  private static final String CLEAR_TABLE = "delete Users; delete Reservations;";
  private PreparedStatement clearTableStatement;

  private static final String CREATE_USER = "INSERT INTO Users(username, password, salt, balance) VALUES(?, ?, ?, ?)";
  private PreparedStatement createUserStatement;

  private static final String GET_USER = "SELECT password, salt FROM Users WHERE username = ?";
  private PreparedStatement getUserStatement;

  private static final String SEARCH = "SELECT TOP (?) fid,day_of_month,carrier_id,flight_num,origin_city,dest_city,actual_time,capacity,price "
          + "FROM Flights WHERE origin_city = ? AND dest_city = ? AND day_of_month =  ? AND canceled != 1 ORDER BY actual_time, fid";
  private PreparedStatement searchStatement;

  private static final String ONE_STOP_SEARCH =
          "SELECT TOP (?) F1.fid, F2.fid, F1.actual_time + F2.actual_time as actual_time, F1.price + F2.price as price" +
                  "            FROM Flights AS F1, Flights AS F2 WHERE F1.origin_city = ? AND F2.dest_city = ? AND F1.dest_city = F2.origin_city" +
                  "            AND F1.day_of_month =  ? AND F2.day_of_month =  ? AND F1.canceled != 1 AND F2.canceled != 1 ORDER BY actual_time, F1.fid, F2.fid ASC";
  private PreparedStatement oneStopSearchStatement;

  private static final String GET_FLIGHT = "SELECT fid,day_of_month,carrier_id,flight_num,origin_city,dest_city,actual_time,capacity,price " +
          "FROM Flights WHERE fid = ?";
  private PreparedStatement getFlightStatement;

  private static final String GET_RESERVATIONS = "SELECT COUNT(*) FROM Reservations WHERE flight_id1 = ? OR flight_id2 = ?";
  private PreparedStatement getReservationsStatement;

  private static final String CHECK_USER_RESERVATIONS = "SELECT COUNT(*) FROM Reservations WHERE uname = ? AND date = ?";
  private PreparedStatement checkUserReservationsStatement;

  private static final String CREATE_RESERVATION = "INSERT INTO Reservations(rid, canceled, paid, date, price, flight_id1, flight_id2, origin_city, dest_city, onehop, uname) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  private PreparedStatement createReservationStatement;

  private static final String GET_MAX_RID = "SELECT MAX(rid) FROM Reservations";
  private PreparedStatement getMaxRIDStatement;

  private static final String CHECK_BALANCE = "SELECT balance FROM Users WHERE username = ?";
  private PreparedStatement checkBalanceStatement;

  private static final String GET_RESERVATION_INFO = "SELECT price, uname FROM Reservations WHERE rid = ? AND paid = 0";
  private PreparedStatement getReservationInfoStatmeent;

  private static final String UPDATE_BALANCE = "UPDATE Users SET balance = ? WHERE username = ?";
  private PreparedStatement updateBalanceStatement;

  private static final String UPDATE_RESERVATION = "UPDATE Reservations SET paid = 1 WHERE rid = ?";
  private PreparedStatement updateReservationStatement;

  private static final String GET_USER_RESERVATIONS = "SELECT rid, paid, flight_id1, flight_id2, onehop FROM Reservations WHERE uname = ? AND canceled != 1 ORDER BY rid ASC";
  private PreparedStatement getUserReservations;

  public Query() throws SQLException, IOException {
    this(null, null, null, null);
  }

  protected Query(String serverURL, String dbName, String adminName, String password)
          throws SQLException, IOException {
    conn = serverURL == null ? openConnectionFromDbConn()
            : openConnectionFromCredential(serverURL, dbName, adminName, password);

    prepareStatements();
    session_login = false;
    session_user = "";
    itineraries = new ArrayList<>();
  }

  /**
   * Return a connecion by using dbconn.properties file
   *
   * @throws SQLException
   * @throws IOException
   */
  public static Connection openConnectionFromDbConn() throws SQLException, IOException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("flightapp.server_url");
    String dbName = configProps.getProperty("flightapp.database_name");
    String adminName = configProps.getProperty("flightapp.username");
    String password = configProps.getProperty("flightapp.password");
    return openConnectionFromCredential(serverURL, dbName, adminName, password);
  }

  /**
   * Return a connecion by using the provided parameter.
   *
   * @param serverURL example: example.database.widows.net
   * @param dbName    database name
   * @param adminName username to login server
   * @param password  password to login server
   *
   * @throws SQLException
   */
  protected static Connection openConnectionFromCredential(String serverURL, String dbName,
                                                           String adminName, String password) throws SQLException {
    String connectionUrl =
            String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
                    dbName, adminName, password);
    Connection conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

    return conn;
  }

  /**
   * Get underlying connection
   */
  public Connection getConnection() {
    return conn;
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   *
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      clearTableStatement.executeUpdate();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /*
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
    // TODO: YOUR CODE HERE
    clearTableStatement = conn.prepareStatement(CLEAR_TABLE);
    createUserStatement = conn.prepareStatement(CREATE_USER);
    getUserStatement = conn.prepareStatement(GET_USER);
    searchStatement = conn.prepareStatement(SEARCH);
    oneStopSearchStatement = conn.prepareStatement(ONE_STOP_SEARCH);
    getFlightStatement = conn.prepareStatement(GET_FLIGHT);
    getReservationsStatement = conn.prepareStatement(GET_RESERVATIONS);
    checkUserReservationsStatement = conn.prepareStatement(CHECK_USER_RESERVATIONS);
    createReservationStatement = conn.prepareStatement(CREATE_RESERVATION);
    getMaxRIDStatement = conn.prepareStatement(GET_MAX_RID);
    checkBalanceStatement = conn.prepareStatement(CHECK_BALANCE);
    updateBalanceStatement = conn.prepareStatement(UPDATE_BALANCE);
    updateReservationStatement = conn.prepareStatement(UPDATE_RESERVATION);
    getReservationInfoStatmeent = conn.prepareStatement(GET_RESERVATION_INFO);
    getUserReservations = conn.prepareStatement(GET_USER_RESERVATIONS);
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged in\n" For all other
   *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    try {
      if(!session_login){
        String caseInsensitiveUsername = username.toLowerCase();
        getUserStatement.clearParameters();
        getUserStatement.setString(1, caseInsensitiveUsername);
        ResultSet rs = getUserStatement.executeQuery();
        rs.next();
        byte[] saltedPassword = rs.getBytes("password");
        byte[] salt = rs.getBytes("salt");
        rs.close();

        byte[] hash = generateHash(password, salt);
        if(Arrays.equals(hash, saltedPassword)) {
          session_login = true;
          session_user = username.toLowerCase();
          return "Logged in as " + username + "\n";
        } else {
          return "Login failed\n";
        }
      }
      return "User already logged in\n";
    } catch (SQLException e) {
      return "Login failed\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  private byte[] generateHash(String password, byte[] salt){
    // Specify the hash parameters
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

    // Generate the hash
    SecretKeyFactory factory = null;
    byte[] hash = null;
    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      hash = factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new IllegalStateException();
    } finally {
      return hash;
    }
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
   *                   otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    try {
      if(initAmount < 0){
        throw new IllegalArgumentException("balance cannot be negative");
      }

      //Case insensitive
      String caseInsensitiveUsername = username.toLowerCase();

      // Generate a random cryptographic salt
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[16];
      random.nextBytes(salt);

      byte[] hash = generateHash(password, salt);

      createUserStatement.clearParameters();
      createUserStatement.setString(1, caseInsensitiveUsername);
      createUserStatement.setBytes(2, hash);
      createUserStatement.setBytes(3, salt);
      createUserStatement.setInt(4, initAmount);
      int success = createUserStatement.executeUpdate();

      return "Created user " + username + "\n";
    } catch(Exception e) {
      System.out.println(e.getMessage());
      return "Failed to create user\n";
    }
    finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination city, on the given day
   * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
   * is searches for direct flights and flights with two "hops." Only searches for up to the number
   * of itineraries given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights, otherwise include
   *                            indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your selection\n". If an error
   *         occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
   *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *         Itinerary numbers in each search should always start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight,
                                   int dayOfMonth, int numberOfItineraries) {
    try {
      try {


        //directFlight?
        searchStatement.clearParameters();
        searchStatement.setInt(1, numberOfItineraries);
        searchStatement.setString(2, originCity);
        searchStatement.setString(3, destinationCity);
        searchStatement.setInt(4, dayOfMonth);
        ResultSet oneHopResults = searchStatement.executeQuery();

        itineraries.clear();

        while (oneHopResults.next()) {
          Flight f = new Flight();
          f.fid = oneHopResults.getInt("fid");
          f.dayOfMonth = oneHopResults.getInt("day_of_month");
          f.carrierId = oneHopResults.getString("carrier_id");
          f.flightNum = oneHopResults.getString("flight_num");
          f.originCity = oneHopResults.getString("origin_city");
          f.destCity = oneHopResults.getString("dest_city");
          f.time = oneHopResults.getInt("actual_time");
          f.capacity = oneHopResults.getInt("capacity");
          f.price = oneHopResults.getInt("price");

          List<Flight> flights = new ArrayList<>();
          flights.add(f);
          Itinerary i = new Itinerary(-1, f.time, f.price, flights, f.dayOfMonth, f.originCity, f.destCity);
          itineraries.add(i);
        }
        oneHopResults.close();

        if(!directFlight && itineraries.size() < numberOfItineraries) {
          int k = numberOfItineraries - itineraries.size();
          oneStopSearchStatement.clearParameters();
          oneStopSearchStatement.setInt(1, k);
          oneStopSearchStatement.setString(2, originCity);
          oneStopSearchStatement.setString(3, destinationCity);
          oneStopSearchStatement.setInt(4, dayOfMonth);
          oneStopSearchStatement.setInt(5, dayOfMonth);

          ResultSet twoHopResults = oneStopSearchStatement.executeQuery();
          while (twoHopResults.next()) {
            int fid1 = twoHopResults.getInt(1);
            int fid2 = twoHopResults.getInt(2);
            int time = twoHopResults.getInt(3);
            int price = twoHopResults.getInt(4);

            Flight f1 = getFlightFromDatabase(fid1);
            Flight f2 = getFlightFromDatabase(fid2);

            List<Flight> flights = new ArrayList<>();
            flights.add(f1);
            flights.add(f2);

            Itinerary i = new Itinerary(-1, time, price, flights, f1.dayOfMonth, f1.originCity, f2.destCity);
            itineraries.add(i);
          }
          twoHopResults.close();
        }
      } catch (SQLException e) {
        e.printStackTrace();
        return "Failed to search\n";
      }


    } finally {
      checkDanglingTransaction();
      if(itineraries.size() == 0){
        return "No flights match your selection\n";
      }
      Collections.sort(itineraries, new compareItineraries());
      StringBuilder str = new StringBuilder();
      for(int i = 0; i < itineraries.size(); i++){
        Itinerary it = itineraries.get(i);
        it.id = i;
        str.append(it);
      }
      return str.toString();
    }
  }

  class compareItineraries implements Comparator<Itinerary> {
    @Override
    public int compare(Itinerary o1, Itinerary o2) {
      if(o1.time == o2.time) {
        if(o1.flights.get(0).fid == o2.flights.get(0).fid) {
          return o1.flights.get(1).fid - o2.flights.get(1).fid;
        }
        return o1.flights.get(0).fid - o2.flights.get(0).fid;
      }
      return o1.time - o2.time;
    }
  }

  private Flight getFlightFromDatabase(int fid) throws SQLException {
    getFlightStatement.clearParameters();
    getFlightStatement.setInt(1, fid);
    ResultSet flight = getFlightStatement.executeQuery();
    flight.next();
    Flight f = new Flight();
    f.fid = flight.getInt("fid");
    f.dayOfMonth = flight.getInt("day_of_month");
    f.carrierId = flight.getString("carrier_id");
    f.flightNum = flight.getString("flight_num");
    f.originCity = flight.getString("origin_city");
    f.destCity = flight.getString("dest_city");
    f.time = flight.getInt("actual_time");
    f.capacity = flight.getInt("capacity");
    f.price = flight.getInt("price");
    flight.close();
    return f;
  }

  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
   *                    the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
   *         If the user is trying to book an itinerary with an invalid ID or without having done a
   *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
   *         a reservation on the same day as the one that they are trying to book now, then return
   *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
   *         failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
   *         where reservationId is a unique number in the reservation system that starts from 1 and
   *         increments by 1 each time a successful reservation is made by any user in the system.
   */
  public String transaction_book(int itineraryId) {
    int rid = -1;
    boolean sameDay = false;
    boolean isBooked = false;
    int success = 0;

    try {

      if(!session_login){
        throw new IllegalStateException();
      }

      boolean deadlock = true;
      Itinerary i = itineraries.get(itineraryId);

      String checkBooked = "SELECT COUNT(*) FROM Reservations WHERE uname = ? AND flight_id1 = ? AND date = ? AND origin_city = ? AND dest_city = ?";
      PreparedStatement checkBookedStatement = conn.prepareStatement(checkBooked);

      while(deadlock){
        try{
          conn.setAutoCommit(false);

          //check user and reservation date
          checkUserReservationsStatement.clearParameters();
          checkUserReservationsStatement.setString(1, session_user);
          checkUserReservationsStatement.setInt(2, i.date);
          ResultSet r = checkUserReservationsStatement.executeQuery();
          r.next();
          int reservationMade = r.getInt(1);
          if(reservationMade > 0){
            conn.rollback();
            sameDay = true;
            throw new IllegalStateException("user already made reservation on that date");
          }

          //check if user has already booked the flight
          checkBookedStatement.clearParameters();
          checkBookedStatement.setString(1, session_user);
          checkBookedStatement.setInt(2, i.flights.get(0).fid);
          checkBookedStatement.setInt(3, i.date);
          checkBookedStatement.setString(4, i.origin_city);
          checkBookedStatement.setString(5, i.dest_city);
          ResultSet booked = checkBookedStatement.executeQuery();
          booked.next();
          isBooked = booked.getInt(1) != 0;
          booked.close();
          if(isBooked) {
            conn.rollback();
            throw new IllegalStateException("flight already booked");
          }

          //check capacity
          for(Flight f : i.flights){
            //get count of reservations with fid = f.fid
            getReservationsStatement.clearParameters();
            getReservationsStatement.setInt(1, f.fid);
            getReservationsStatement.setInt(2, f.fid);
            r = getReservationsStatement.executeQuery();

            r.next();
            int reserved_capacity = r.getInt(1);
            if(f.capacity - reserved_capacity <= 0){
              conn.rollback();
              throw new IllegalStateException("capacity is exceeded");
            }
            r.close();
          }



          ResultSet ridResults = getMaxRIDStatement.executeQuery();
          ridResults.next();
          rid = ridResults.getInt(1) + 1;
          ridResults.close();

          //if all checks pass then insert into reservation row
          createReservationStatement.clearParameters();
          createReservationStatement.setInt(1, rid);
          createReservationStatement.setInt(2, 0);
          createReservationStatement.setInt(3, 0);
          createReservationStatement.setInt(4, i.date);
          createReservationStatement.setInt(5, i.price);
          createReservationStatement.setInt(6, i.flights.get(0).fid);
          if(i.flights.size() > 1){
            createReservationStatement.setInt(7, i.flights.get(1).fid);
          } else {
            createReservationStatement.setNull(7, java.sql.Types.INTEGER);
          }
          createReservationStatement.setString(8, i.origin_city);
          createReservationStatement.setString(9, i.dest_city);
          createReservationStatement.setInt(10, i.flights.size() == 1 ? 0 : 1);
          createReservationStatement.setString(11, session_user);

          success = createReservationStatement.executeUpdate();

          conn.commit();
        } catch(SQLException e){
          deadlock = isDeadLock(e);
          conn.rollback();
        }
      }
    } catch(Exception e){
      conn.rollback();
      conn.setAutoCommit(true);
    } finally {
      checkDanglingTransaction();
      if(!session_login){
        return "Cannot book reservations, not logged in\n";
      } else if(success > 0){
        return "Booked flight(s), reservation ID: " + rid + "\n";
      } else if(sameDay){
        return "You cannot book two flights in the same day\n";
      } else if(isBooked){
        return "Booking failed\n";
      }  else if(itineraries.size() == 0 || itineraryId < 0 || itineraryId >= itineraries.size()){
        return "No such itinerary " + itineraryId + "\n";
      }  else {
        return "Booking failed\n";
      }
    }
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
   *         is not found / not under the logged in user's name, then return "Cannot find unpaid
   *         reservation [reservationId] under user: [username]\n" If the user does not have enough
   *         money in their account, then return "User has only [balance] in account but itinerary
   *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
   *         [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining balance:
   *         [balance]\n" where [balance] is the remaining balance in the user's account.
   */
  public String transaction_pay(int reservationId) {
    int newBalance = -1;
    boolean noReservation = false;
    int balance = -1;
    int price = -1;

    try {
      if(!session_login){
        throw new IllegalStateException();
      }
      boolean deadlock = false;

      conn.setAutoCommit(false);

      while(!deadlock){
        //Check reservation status
        getReservationInfoStatmeent.clearParameters();
        getReservationInfoStatmeent.setInt(1, reservationId);
        ResultSet r = getReservationInfoStatmeent.executeQuery();


        if(r.next() == false){
          noReservation = true;
          conn.rollback();
          throw new IllegalStateException();
        } else {
          try{
            price = r.getInt(1);
            String username = r.getString(2);
            if(!username.equals(session_user)){
              conn.rollback();
              throw new IllegalStateException();
            }

            checkBalanceStatement.clearParameters();
            checkBalanceStatement.setString(1, session_user);
            ResultSet b = checkBalanceStatement.executeQuery();

            b.next();
            balance = b.getInt(1);
            b.close();
            if(balance < price){
              conn.rollback();
              throw new IllegalStateException();
            }


            updateBalanceStatement.clearParameters();
            updateBalanceStatement.setInt(1, balance - price);
            updateBalanceStatement.setString(2, session_user);

            int success = updateBalanceStatement.executeUpdate();

            updateReservationStatement.clearParameters();
            updateReservationStatement.setInt(1, reservationId);
            updateReservationStatement.executeUpdate();

            newBalance = balance - price;
            conn.commit();
          } catch(SQLException e){
            e.getErrorCode();
            deadlock = isDeadLock(e);
            conn.rollback();
          }
        }
        r.close();
      }
      conn.setAutoCommit(true);
    } catch(Exception e){

    }
    finally {
      checkDanglingTransaction();

      if(newBalance >= 0) {
        return "Paid reservation: " + reservationId + " remaining balance: " + newBalance + "\n";
      } else if(!session_login){
        return "Cannot pay, not logged in\n";
      } else if (noReservation){
        return "Cannot find unpaid reservation " + reservationId + " under user: " + session_user +"\n";
      } else if(balance < price){
        return "User has only " + balance + " in account but itinerary costs " + price + "\n";
      } else {
        return "Failed to pay for reservation " + reservationId + "\n";
      }
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
   *         the user has no reservations, then return "No reservations found\n" For all other
   *         errors, return "Failed to retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
   *         reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
   *         [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
   *         reservation]\n ...
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    try {
      if(!session_login){
        return "Cannot view reservations, not logged in\n";
      }

      //check if the user has reservations
      getUserReservations.clearParameters();
      getUserReservations.setString(1, session_user);
      ResultSet r = getUserReservations.executeQuery();

      StringBuilder str = new StringBuilder();
      if(r.next() == false){
        return "No reservations found\n";
      } else {
        do {
          //rid, paid, flight_id1, flight_id2, onehop
          Reservation reservation = new Reservation();
          reservation.rid = r.getInt(1);
          reservation.paid = r.getInt(2) == 1;
          int fid1 = r.getInt(3);
          int fid2 = r.getInt(4);
          boolean onehop = r.getInt(5) == 1;

          List<Flight> flights = new ArrayList<>();
          Flight f1 = getFlightFromDatabase(fid1);
          flights.add(f1);
          if(onehop){
            Flight f2 = getFlightFromDatabase(fid2);
            flights.add(f2);
          }

          reservation.flights = flights;
          str.append(reservation);
        } while(r.next());
      }
      r.close();
      return str.toString();
    } catch(Exception e){
      return "Failed to retrieve reservations\n";
    }
    finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
   *         all other errors, return "Failed to cancel reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    try {
      if(!session_login){
        return "Cannot cancel reservations, not logged in\n";
      }
      boolean deadlock = false;
      while(!deadlock) {
        try{
          String reservation_query = "SELECT price, uname, paid FROM Reservations WHERE rid = ? AND canceled = 0";
          PreparedStatement reservationQueryStatement = conn.prepareStatement(reservation_query);

          String cancel_res = "UPDATE Reservations SET canceled = 1, paid = 0 WHERE rid = ?";
          PreparedStatement cancelResStatement = conn.prepareStatement(cancel_res);

          String update_user = "UPDATE Users SET balance = ? WHERE username = ?";
          PreparedStatement updateUserStatement = conn.prepareStatement(update_user);

          conn.setAutoCommit(false);

          //Check reservation status
          reservationQueryStatement.clearParameters();
          reservationQueryStatement.setInt(1, reservationId);
          ResultSet r = reservationQueryStatement.executeQuery();

          if(r.next() == false) {
            conn.rollback();
            throw new IllegalStateException();
          } else {
            do{
              int price = r.getInt(1);
              String username = r.getString(2);
              boolean paid = r.getInt(3) == 1;
              if(!username.equals(session_user)){
                conn.rollback();
                throw new IllegalStateException();
              }

              //valid user and valid id
              cancelResStatement.setInt(1, reservationId);
              int success = cancelResStatement.executeUpdate();

              if(paid) {
                checkBalanceStatement.clearParameters();
                checkBalanceStatement.setString(1, session_user);
                ResultSet b = checkBalanceStatement.executeQuery();

                b.next();
                int balance = b.getInt(1);
                b.close();

                updateUserStatement.setInt(1, balance + price);
                updateUserStatement.setString(2, session_user);
                updateUserStatement.executeUpdate();
              }
              conn.commit();
              return "Canceled reservation " + reservationId + "\n";
            } while(r.next());
          }
        } catch(SQLException e) {
          deadlock = isDeadLock(e);
          conn.rollback();
        }
      }
      return "Failed to cancel reservation " + reservationId + "\n";
    } catch(Exception e){
      return "Failed to cancel reservation " + reservationId + "\n";
    }finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }

  /**
   * Throw IllegalStateException if transaction not completely complete, rollback.
   *
   */
  private void checkDanglingTransaction() {
    try {
      try (ResultSet rs = tranCountStatement.executeQuery()) {
        rs.next();
        int count = rs.getInt("tran_count");
        if (count > 0) {
          throw new IllegalStateException(
                  "Transaction not fully commit/rollback. Number of transaction in process: " + count);
        }
      } finally {
        conn.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("Database error", e);
    }
  }

  private static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;

    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
              + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
              + " Capacity: " + capacity + " Price: " + price;
    }
  }

  class Itinerary {
    public int id;
    public int time;
    public int date;
    public int price;
    public List<Flight> flights;
    public String origin_city;
    public String dest_city;

    public Itinerary(int id, int time, int price, List<Flight> flights, int date, String origin_city, String dest_city) {
      this.id = id;
      this.price = price;
      this.time = time;
      this.flights = flights;
      this.date = date;
      this.origin_city = origin_city;
      this.dest_city = dest_city;
    }

    @Override
    public String toString() {
      StringBuilder str = new StringBuilder();
      str.append("Itinerary " + this.id + ": " + flights.size() + " flight(s), " + this.time + " minutes\n");
      for (Flight f : flights) {
        str.append(f);
        str.append("\n");
      }
      return str.toString();
    }
  }

  class Reservation {
    public int rid;
    public boolean paid;
    public List<Flight> flights;

    @Override
    public String toString() {
      StringBuilder str = new StringBuilder();
      str.append("Reservation " + rid + " paid: " + paid + ":\n");
      for(Flight f : flights){
        str.append(f);
        str.append("\n");
      }
      return str.toString();
    }
  }
}