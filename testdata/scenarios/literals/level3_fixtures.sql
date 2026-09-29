-- Seed data written the way real dumps are: separators inside numbers,
-- IBANs in groups of four.
INSERT INTO customers (name, email, card, iban) VALUES
  ('Pham Quoc Bao', 'bao.pham77@ledgermail-demo.com', '2221-0288-7754-3678', 'DE27 1197 1024 5332 2468 84'),
  ('Hoang Thu Trang', 'trang.hoang@ledgermail-demo.com', '3782 309506 48938', NULL);
INSERT INTO employees (name, ssn) VALUES ('Dang Van Khoa', '002-53-5920');
-- Look-alikes that are not data: a failed Luhn check, a wrong IBAN
-- checksum and reserved SSN ranges.
INSERT INTO orders (ref) VALUES ('4539567730222925'), ('DE54611003851861547264');
INSERT INTO employees (name, ssn) VALUES ('Reserved', '666-12-3456'), ('Reserved', '900-12-3456'), ('Reserved', '000-12-3456');
