CREATE TABLE Users(
    username VARCHAR(20) PRIMARY KEY,
    password VARBINARY(128),
    salt VARCHAR(20),
    balance INT
);

CREATE TABLE Reservations(
    rid INT PRIMARY KEY,
    canceled INT, -- boolean 1: canceled, 0: not canceled
    paid INT, -- boolean 1: paid, 0: not paid
    date INT, -- the day of the reservation
    price INT,
    flight_id1 INT REFERENCES Flights(fid) NOT NULL,
    flight_id2 INT REFERENCES Flights(fid),
    origin_city VARCHAR(20),
    dest_city VARCHAR (20),
    onehop INT, --boolean 1: is a onehop, 0: direct flight
    uname VARCHAR(20) REFERENCES Users(username) ON DELETE CASCADE,
);