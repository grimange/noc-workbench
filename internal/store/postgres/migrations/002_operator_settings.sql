CREATE TABLE operator_setting (
    id smallint PRIMARY KEY CHECK (id = 1),
    note text NOT NULL CHECK (octet_length(note) <= 4096)
);
