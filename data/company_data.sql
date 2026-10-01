-- SecureLLM-Enterprise demo dataset (deterministic, seed 42)
-- Regenerate at any time: python scripts/seed_company_data.py
BEGIN TRANSACTION;
-- ============ company.db ============
CREATE TABLE users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL,
    department    TEXT NOT NULL,
    clearance     TEXT NOT NULL,
    is_active     INTEGER DEFAULT 1,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP
);
CREATE TABLE employees (
            id INTEGER PRIMARY KEY, name TEXT, department TEXT, role TEXT,
            email TEXT, phone TEXT, salary INTEGER,
            designation TEXT, bonus INTEGER DEFAULT 0,
            join_date TEXT, manager_id INTEGER, address TEXT);
CREATE TABLE departments (id INTEGER PRIMARY KEY, name TEXT, manager TEXT);
CREATE TABLE documents (
            doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT UNIQUE NOT NULL, content TEXT NOT NULL,
            department TEXT NOT NULL,
            sensitivity TEXT NOT NULL CHECK (sensitivity IN
                ('Public','Internal','Confidential','Restricted')),
            min_clearance TEXT NOT NULL CHECK (min_clearance IN
                ('L1','L2','L3','L4','L5')),
            namespace TEXT NOT NULL,
            file_path TEXT NOT NULL);
CREATE VIEW employees_tech_view AS
            SELECT id, name, department, role FROM employees WHERE department='Tech';
CREATE VIEW employees_public_view AS
            SELECT id, name, department, role, join_date FROM employees;
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('1', 'admin', '$2b$12$m93voVm2lqU8WOF33COnvOLYaMl6LVTOrPQjHAKyl2eaABE41IpG6', 'System Administrator', 'admin@corp.example.com', 'Admin', 'IT', 'L5', '1', '2026-10-01 17:01:57', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('2', 'ceo', '$2b$12$hd5P5ozNeXVoUX5EoLzmJOYA8B0110YwLZdmVlfIROJYKHT5KeWB2', 'Rajesh Kumar', 'rajesh.kumar@corp.example.com', 'Executive', 'Executive', 'L5', '1', '2026-10-01 17:01:57', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('3', 'cto', '$2b$12$YsjCWSWXjTj1c1SRWqqjW.4Ksvf9rbFmDMZ/AEF2fcy.4X5GbLGSK', 'Priya Sharma', 'priya.sharma@corp.example.com', 'Executive', 'Executive', 'L5', '1', '2026-10-01 17:01:57', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('4', 'hr_manager', '$2b$12$udb/3O3Fcxg.M/QbGsGq4eU5h05yN2PJV51IMc0S4zBJx1tzpfEx6', 'Anjali Verma', 'anjali.verma@corp.example.com', 'HR_Manager', 'HR', 'L4', '1', '2026-10-01 17:01:58', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('5', 'hr_emp1', '$2b$12$sX6TKavxF/ZMV1ti7u/yTeuQxb.gY32oRAXCYJl0nGuJ9jrRSc.sS', 'Suresh Patel', 'suresh.patel@corp.example.com', 'HR_Employee', 'HR', 'L3', '1', '2026-10-01 17:01:58', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('6', 'tech_lead', '$2b$12$4fDdI02u.zFaX8jVsJprpuKmRapWSxFTg.8xVHwPA9J1xJXhti8kS', 'Vikram Singh', 'vikram.singh@corp.example.com', 'Tech_Lead', 'Tech', 'L4', '1', '2026-10-01 17:01:58', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('7', 'tech_eng1', '$2b$12$KsAWNbTsnSJL4cO79C.y8.FNsjaKdySB8YnV7bEicEKcO642HACse', 'Arun Mehta', 'arun.mehta@corp.example.com', 'Tech_Engineer', 'Tech', 'L3', '1', '2026-10-01 17:01:58', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('8', 'tech_eng2', '$2b$12$QAZRtU0iCtzqS1nEtC.YRewiG9/mBYISQqlxmHEjHPYRvpWFD4TRm', 'Neha Gupta', 'neha.gupta@corp.example.com', 'Tech_Engineer', 'Tech', 'L3', '1', '2026-10-01 17:01:59', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('9', 'biz_analyst', '$2b$12$qMnOGVjlhBKplDhqyc5vMetguV7x8g6U95BHWham6xMysjBCfm8PW', 'Rahul Joshi', 'rahul.joshi@corp.example.com', 'Business_Analyst', 'Business', 'L3', '1', '2026-10-01 17:01:59', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('10', 'fin_manager', '$2b$12$Fpf3WD2CD5boKpTHGuV/V.sbhcZJvA//mY8KKNG3ITvRy4P8GIZkS', 'Meera Iyer', 'meera.iyer@corp.example.com', 'Finance_Manager', 'Finance', 'L4', '1', '2026-10-01 17:01:59', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('11', 'alice', '$2b$12$1jMsDcJ9OqjTmZu7Mzz.wOjBbCqMoi73yEv0DpunPghqoPOWRMXBe', 'Alice Fernandes', 'alice.fernandes@corp.example.com', 'Tech_Employee', 'Tech', 'L2', '1', '2026-10-01 17:01:59', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('12', 'hr_hari', '$2b$12$iGTmR5ov/lgAJV0KFqrfs.Sx.22rvY5RnKwoXAqZrF9ZcA8i/3qqi', 'Hari Krishnan', 'hari.krishnan@corp.example.com', 'HR_Manager', 'HR', 'L4', '1', '2026-10-01 17:02:00', NULL);
INSERT INTO users (user_id, username, password_hash, full_name, email, role, department, clearance, is_active, created_at, last_login) VALUES ('13', 'ceo_meera', '$2b$12$JljDIBAdTdKg0XXUNXb8cuTCbgduWQfz0K26bQtn5TzfBE2TfLnWe', 'Meera Nair', 'meera.nair@corp.example.com', 'Executive', 'Executive', 'L5', '1', '2026-10-01 17:02:00', NULL);
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('1', 'Raj Iyer', 'HR', 'Recruiter', 'raj.iyer@corp.example.com', '+1 (555) 045-4012', '88500', 'Recruiter', '4750', '2020-12-24', '86', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('2', 'Kabir Iyer', 'HR', 'Recruiter', 'kabir.iyer@corp.example.com', '+1 (555) 064-0520', '63500', 'Recruiter', '4500', '2021-07-27', '89', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('3', 'Rohan Singh', 'Tech', 'Engineer', 'rohan.singh@corp.example.com', '+1 (555) 081-3257', '149500', 'Engineer', '12250', '2024-03-30', '38', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('4', 'Tara Joshi', 'Sales', 'Sales Manager', 'tara.joshi@corp.example.com', '+1 (555) 045-0106', '75000', 'Sales Manager', '5000', '2023-11-09', '42', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('5', 'Sam Pillai', 'Business', 'Manager', 'sam.pillai@corp.example.com', '+1 (555) 029-3527', '113000', 'Manager', '6250', '2022-10-26', '22', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('6', 'Priya Nair', 'Sales', 'AE', 'priya.nair@corp.example.com', '+1 (555) 055-5635', '132000', 'AE', '1500', '2019-10-09', '101', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('7', 'Arjun Patel', 'Sales', 'Sales Manager', 'arjun.patel@corp.example.com', '+1 (555) 025-6201', '65000', 'Sales Manager', '500', '2020-09-01', '85', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('8', 'Kavya Das', 'Business', 'Director', 'kavya.das@corp.example.com', '+1 (555) 034-1139', '75500', 'Director', '3000', '2019-07-11', '98', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('9', 'Pooja Joshi', 'Business', 'Analyst', 'pooja.joshi@corp.example.com', '+1 (555) 039-1654', '118500', 'Analyst', '250', '2024-05-02', '41', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('10', 'Arjun Bose', 'Business', 'Analyst', 'arjun.bose@corp.example.com', '+1 (555) 057-5820', '96500', 'Analyst', '7250', '2017-10-06', '118', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('11', 'Pooja Kulkarni', 'HR', 'Recruiter', 'pooja.kulkarni@corp.example.com', '+1 (555) 091-2803', '128000', 'Recruiter', '5000', '2022-08-14', '84', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('12', 'Leela Joshi', 'Tech', 'Security Analyst', 'leela.joshi@corp.example.com', '+1 (555) 058-4422', '151000', 'Security Analyst', '9500', '2017-12-20', '98', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('13', 'Isha Mehta', 'HR', 'HR Partner', 'isha.mehta@corp.example.com', '+1 (555) 014-5168', '111000', 'HR Partner', '8750', '2015-10-03', '77', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('14', 'Arjun Nair', 'Tech', 'SRE', 'arjun.nair@corp.example.com', '+1 (555) 037-8179', '130500', 'SRE', '1000', '2019-07-27', '119', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('15', 'Manav Bose', 'Tech', 'SRE', 'manav.bose@corp.example.com', '+1 (555) 027-4040', '151500', 'SRE', '10750', '2015-03-12', '77', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('16', 'Kavya Kulkarni', 'Sales', 'Sales Manager', 'kavya.kulkarni@corp.example.com', '+1 (555) 061-5930', '83000', 'Sales Manager', '1500', '2016-03-04', '32', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('17', 'Kabir Chauhan', 'HR', 'HR Partner', 'kabir.chauhan@corp.example.com', '+1 (555) 024-2504', '80000', 'HR Partner', '3500', '2023-05-27', '113', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('18', 'Nisha Pillai', 'HR', 'HRBP', 'nisha.pillai@corp.example.com', '+1 (555) 058-9763', '119500', 'HRBP', '0', '2023-12-02', '115', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('19', 'Suresh Kulkarni', 'HR', 'Recruiter', 'suresh.kulkarni@corp.example.com', '+1 (555) 024-8797', '94000', 'Recruiter', '6750', '2021-06-01', '97', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('20', 'Vikram Mehta', 'HR', 'HRBP', 'vikram.mehta@corp.example.com', '+1 (555) 065-2591', '118000', 'HRBP', '8750', '2015-07-07', '95', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('21', 'Aarav Kulkarni', 'Tech', 'Engineer', 'aarav.kulkarni@corp.example.com', '+1 (555) 090-4889', '144500', 'Engineer', '3250', '2021-11-09', '120', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('22', 'Neha Singh', 'Tech', 'SRE', 'neha.singh@corp.example.com', '+1 (555) 030-8837', '147500', 'SRE', '8250', '2020-11-27', '63', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('23', 'Sara Sharma', 'Business', 'Manager', 'sara.sharma@corp.example.com', '+1 (555) 012-1832', '116000', 'Manager', '750', '2023-05-16', '59', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('24', 'Manav Das', 'Finance', 'Accountant', 'manav.das@corp.example.com', '+1 (555) 040-9295', '133458', 'Accountant', '7750', '2021-01-30', '92', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('25', 'Rohan Chauhan', 'HR', 'Recruiter', 'rohan.chauhan@corp.example.com', '+1 (555) 026-2103', '120500', 'Recruiter', '8750', '2023-12-15', '68', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('26', 'Kavya Reddy', 'Business', 'Director', 'kavya.reddy@corp.example.com', '+1 (555) 087-6932', '97000', 'Director', '4000', '2015-10-01', '86', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('27', 'Sara Singh', 'Business', 'Manager', 'sara.singh@corp.example.com', '+1 (555) 095-6118', '126000', 'Manager', '750', '2016-11-27', '36', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('28', 'Priya Joshi', 'Tech', 'Engineer', 'priya.joshi@corp.example.com', '+1 (555) 053-0344', '155000', 'Engineer', '3000', '2019-12-06', '117', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('29', 'Kavya Joshi', 'Tech', 'Engineer', 'kavya.joshi@corp.example.com', '+1 (555) 019-0964', '109000', 'Engineer', '750', '2021-03-21', '14', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('30', 'Rohan Patel', 'Business', 'Analyst', 'rohan.patel@corp.example.com', '+1 (555) 075-3899', '105500', 'Analyst', '5500', '2021-10-19', '87', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('31', 'Pooja Chauhan', 'Tech', 'Senior Engineer', 'pooja.chauhan@corp.example.com', '+1 (555) 083-9440', '140500', 'Senior Engineer', '6750', '2018-03-23', '90', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('32', 'Isha Chauhan', 'Sales', 'AE', 'isha.chauhan@corp.example.com', '+1 (555) 022-1588', '139000', 'AE', '750', '2022-02-09', '55', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('33', 'Tara Rao', 'Sales', 'Sr AE', 'tara.rao@corp.example.com', '+1 (555) 069-0887', '138500', 'Sr AE', '6000', '2015-10-08', '21', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('34', 'Diya Kapoor', 'Business', 'Analyst', 'diya.kapoor@corp.example.com', '+1 (555) 041-3139', '94000', 'Analyst', '4000', '2023-01-17', '22', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('35', 'Kavya Bose', 'Tech', 'Security Analyst', 'kavya.bose@corp.example.com', '+1 (555) 033-4563', '139000', 'Security Analyst', '2000', '2020-06-05', '46', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('36', 'Isha Nair', 'Sales', 'Sales Manager', 'isha.nair@corp.example.com', '+1 (555) 022-0828', '138000', 'Sales Manager', '8750', '2017-11-01', '15', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('37', 'Kavya Sharma', 'HR', 'HR Partner', 'kavya.sharma@corp.example.com', '+1 (555) 031-6658', '122000', 'HR Partner', '5250', '2019-05-29', '75', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('38', 'Riya Singh', 'Sales', 'AE', 'riya.singh@corp.example.com', '+1 (555) 031-6209', '55000', 'AE', '3250', '2016-10-13', '87', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('39', 'Dev Kulkarni', 'Sales', 'Sr AE', 'dev.kulkarni@corp.example.com', '+1 (555) 064-9105', '139500', 'Sr AE', '9750', '2022-10-28', '76', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('40', 'Sam Chauhan', 'Tech', 'Senior Engineer', 'sam.chauhan@corp.example.com', '+1 (555) 047-3566', '87000', 'Senior Engineer', '250', '2015-05-04', '65', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('41', 'Amit Patel', 'Business', 'Analyst', 'amit.patel@corp.example.com', '+1 (555) 016-9571', '131000', 'Analyst', '10250', '2019-11-27', '34', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('42', 'Suresh Reddy', 'HR', 'Recruiter', 'suresh.reddy@corp.example.com', '+1 (555) 020-3044', '68500', 'Recruiter', '3000', '2024-10-19', '40', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('43', 'Neha Nair', 'Tech', 'Security Analyst', 'neha.nair@corp.example.com', '+1 (555) 025-9333', '111500', 'Security Analyst', '4750', '2019-12-08', '70', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('44', 'Tara Mehta', 'Business', 'Analyst', 'tara.mehta@corp.example.com', '+1 (555) 095-5147', '100500', 'Analyst', '6000', '2016-08-13', '75', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('45', 'Arjun Kapoor', 'Tech', 'SRE', 'arjun.kapoor@corp.example.com', '+1 (555) 068-5180', '89000', 'SRE', '6000', '2023-05-15', '25', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('46', 'Aarav Bose', 'HR', 'HR Partner', 'aarav.bose@corp.example.com', '+1 (555) 078-3492', '124500', 'HR Partner', '1250', '2020-03-02', '84', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('47', 'Arjun Gupta', 'Business', 'Analyst', 'arjun.gupta@corp.example.com', '+1 (555) 041-6054', '106000', 'Analyst', '5250', '2015-12-18', '103', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('48', 'Ananya Bose', 'Finance', 'FP&A Analyst', 'ananya.bose@corp.example.com', '+1 (555) 093-8666', '134096', 'FP&A Analyst', '9500', '2019-05-12', '12', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('49', 'Pooja Das', 'HR', 'HR Partner', 'pooja.das@corp.example.com', '+1 (555) 043-1891', '73500', 'HR Partner', '4000', '2021-07-08', '43', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('50', 'Leela Gupta', 'Business', 'Manager', 'leela.gupta@corp.example.com', '+1 (555) 087-3450', '113500', 'Manager', '7000', '2016-04-10', '81', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('51', 'Vivaan Kulkarni', 'Sales', 'Sr AE', 'vivaan.kulkarni@corp.example.com', '+1 (555) 016-1512', '136000', 'Sr AE', '4750', '2015-08-03', '58', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('52', 'Tara Kulkarni', 'HR', 'HR Partner', 'tara.kulkarni@corp.example.com', '+1 (555) 052-2143', '93500', 'HR Partner', '5500', '2020-12-31', '37', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('53', 'Kavya Pillai', 'HR', 'HR Partner', 'kavya.pillai@corp.example.com', '+1 (555) 019-2442', '129500', 'HR Partner', '9250', '2016-02-26', '83', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('54', 'Diya Rao', 'Tech', 'Security Analyst', 'diya.rao@corp.example.com', '+1 (555) 026-0685', '119000', 'Security Analyst', '8000', '2023-08-22', '71', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('55', 'Sneha Patel', 'Business', 'Analyst', 'sneha.patel@corp.example.com', '+1 (555) 097-4088', '83000', 'Analyst', '5000', '2021-04-14', '59', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('56', 'Sneha Pillai', 'Tech', 'Senior Engineer', 'sneha.pillai@corp.example.com', '+1 (555) 030-2900', '132500', 'Senior Engineer', '250', '2016-09-01', '13', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('57', 'Aarav Reddy', 'Business', 'Manager', 'aarav.reddy@corp.example.com', '+1 (555) 095-4065', '104000', 'Manager', '1250', '2024-10-16', '79', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('58', 'Ananya Iyer', 'Sales', 'AE', 'ananya.iyer@corp.example.com', '+1 (555) 070-3644', '80500', 'AE', '3500', '2023-03-31', '88', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('59', 'Karan Bose', 'Business', 'Manager', 'karan.bose@corp.example.com', '+1 (555) 039-3652', '73000', 'Manager', '1250', '2023-11-13', '19', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('60', 'Pooja Singh', 'Sales', 'Sr AE', 'pooja.singh@corp.example.com', '+1 (555) 045-1137', '90500', 'Sr AE', '1750', '2023-06-07', '23', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('61', 'Sneha Kapoor', 'Business', 'Analyst', 'sneha.kapoor@corp.example.com', '+1 (555) 024-4279', '92500', 'Analyst', '5500', '2022-02-04', '98', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('62', 'Amit Kulkarni', 'HR', 'HR Partner', 'amit.kulkarni@corp.example.com', '+1 (555) 086-7119', '104000', 'HR Partner', '7250', '2022-12-28', '99', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('63', 'Leela Mehta', 'Sales', 'Sales Manager', 'leela.mehta@corp.example.com', '+1 (555) 075-1894', '104000', 'Sales Manager', '4750', '2023-06-09', '35', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('64', 'Manav Singh', 'Business', 'Analyst', 'manav.singh@corp.example.com', '+1 (555) 065-0027', '136500', 'Analyst', '11000', '2019-10-13', '40', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('65', 'Rohan Mehta', 'Business', 'Director', 'rohan.mehta@corp.example.com', '+1 (555) 025-4920', '134500', 'Director', '2500', '2015-11-29', '87', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('66', 'Meera Pillai', 'Business', 'Manager', 'meera.pillai@corp.example.com', '+1 (555) 099-4844', '140500', 'Manager', '4750', '2022-01-25', '80', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('67', 'Kabir Singh', 'Sales', 'Sales Manager', 'kabir.singh@corp.example.com', '+1 (555) 058-2851', '133500', 'Sales Manager', '2500', '2022-09-03', '20', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('68', 'Amit Das', 'Sales', 'Sales Manager', 'amit.das@corp.example.com', '+1 (555) 010-4978', '91500', 'Sales Manager', '500', '2016-10-15', '65', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('69', 'Vivaan Pillai', 'Business', 'Manager', 'vivaan.pillai@corp.example.com', '+1 (555) 066-7244', '97000', 'Manager', '3750', '2015-08-30', '50', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('70', 'Suresh Chauhan', 'Tech', 'Engineer', 'suresh.chauhan@corp.example.com', '+1 (555) 046-8445', '159000', 'Engineer', '10750', '2023-11-03', '48', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('71', 'Rahul Nair', 'Tech', 'SRE', 'rahul.nair@corp.example.com', '+1 (555) 038-3262', '98500', 'SRE', '7250', '2020-04-21', '91', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('72', 'Aarav Patel', 'Finance', 'Accountant', 'aarav.patel@corp.example.com', '+1 (555) 088-1193', '74669', 'Accountant', '500', '2024-07-06', '79', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('73', 'Tara Singh', 'Sales', 'Sr AE', 'tara.singh@corp.example.com', '+1 (555) 061-3997', '73500', 'Sr AE', '2750', '2018-01-23', '69', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('74', 'Raj Sharma', 'HR', 'HRBP', 'raj.sharma@corp.example.com', '+1 (555) 038-2881', '126000', 'HRBP', '250', '2015-01-01', '115', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('75', 'Nikhil Patel', 'Tech', 'Engineer', 'nikhil.patel@corp.example.com', '+1 (555) 068-2184', '139000', 'Engineer', '750', '2021-01-20', '65', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('76', 'Pooja Mehta', 'Sales', 'Sales Manager', 'pooja.mehta@corp.example.com', '+1 (555) 074-6991', '125000', 'Sales Manager', '10250', '2019-06-20', '118', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('77', 'Nikhil Reddy', 'Sales', 'Sr AE', 'nikhil.reddy@corp.example.com', '+1 (555) 043-4050', '136500', 'Sr AE', '8250', '2021-04-21', '113', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('78', 'Arjun Chauhan', 'Tech', 'SRE', 'arjun.chauhan@corp.example.com', '+1 (555) 066-1269', '116500', 'SRE', '2250', '2022-09-25', '113', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('79', 'Isha Kulkarni', 'Business', 'Manager', 'isha.kulkarni@corp.example.com', '+1 (555) 079-1320', '87500', 'Manager', '6750', '2024-07-19', '48', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('80', 'Kabir Joshi', 'Sales', 'Sales Manager', 'kabir.joshi@corp.example.com', '+1 (555) 029-3505', '63000', 'Sales Manager', '3750', '2019-03-02', '5', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('81', 'Tara Pillai', 'Business', 'Director', 'tara.pillai@corp.example.com', '+1 (555) 069-6812', '77500', 'Director', '0', '2023-06-24', '72', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('82', 'Dev Sharma', 'Sales', 'Sr AE', 'dev.sharma@corp.example.com', '+1 (555) 010-5763', '93000', 'Sr AE', '500', '2023-07-08', '97', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('83', 'Vikram Kapoor', 'Sales', 'Sales Manager', 'vikram.kapoor@corp.example.com', '+1 (555) 079-9883', '83000', 'Sales Manager', '6500', '2023-07-18', '42', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('84', 'Riya Joshi', 'Business', 'Manager', 'riya.joshi@corp.example.com', '+1 (555) 072-0475', '119500', 'Manager', '9750', '2019-09-24', '45', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('85', 'Rahul Kapoor', 'Tech', 'Security Analyst', 'rahul.kapoor@corp.example.com', '+1 (555) 026-8751', '83000', 'Security Analyst', '1250', '2015-02-19', '58', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('86', 'Sara Kapoor', 'HR', 'HR Partner', 'sara.kapoor@corp.example.com', '+1 (555) 092-7022', '77000', 'HR Partner', '1500', '2015-10-28', '49', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('87', 'Divya Bose', 'Tech', 'Engineer', 'divya.bose@corp.example.com', '+1 (555) 043-6211', '121500', 'Engineer', '1250', '2021-03-05', '76', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('88', 'Vivaan Bose', 'Business', 'Manager', 'vivaan.bose@corp.example.com', '+1 (555) 058-4558', '123500', 'Manager', '6500', '2017-06-28', '109', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('89', 'Riya Sharma', 'HR', 'HRBP', 'riya.sharma@corp.example.com', '+1 (555) 038-1124', '65000', 'HRBP', '1750', '2020-08-15', '18', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('90', 'Vikram Sharma', 'Tech', 'Senior Engineer', 'vikram.sharma@corp.example.com', '+1 (555) 012-2496', '110500', 'Senior Engineer', '250', '2019-10-08', '118', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('91', 'Pooja Iyer', 'Tech', 'Security Analyst', 'pooja.iyer@corp.example.com', '+1 (555) 099-4198', '127000', 'Security Analyst', '1500', '2023-01-02', '114', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('92', 'Vikram Reddy', 'Business', 'Analyst', 'vikram.reddy@corp.example.com', '+1 (555) 084-0420', '109500', 'Analyst', '4500', '2015-07-31', '85', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('93', 'Amit Kapoor', 'Sales', 'Sales Manager', 'amit.kapoor@corp.example.com', '+1 (555) 035-1245', '130500', 'Sales Manager', '5750', '2024-04-11', '36', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('94', 'Sam Joshi', 'HR', 'Recruiter', 'sam.joshi@corp.example.com', '+1 (555) 048-9837', '75000', 'Recruiter', '6000', '2019-01-17', '69', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('95', 'Nisha Patel', 'Business', 'Director', 'nisha.patel@corp.example.com', '+1 (555) 064-6071', '78500', 'Director', '5500', '2017-06-04', '8', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('96', 'Suresh Mehta', 'Finance', 'Controller', 'suresh.mehta@corp.example.com', '+1 (555) 072-1729', '73115', 'Controller', '3000', '2022-09-24', '62', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('97', 'Sneha Bose', 'Tech', 'Security Analyst', 'sneha.bose@corp.example.com', '+1 (555) 032-8548', '114500', 'Security Analyst', '500', '2023-12-25', '46', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('98', 'Neha Chauhan', 'Sales', 'Sr AE', 'neha.chauhan@corp.example.com', '+1 (555) 085-4397', '96000', 'Sr AE', '500', '2022-08-10', '73', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('99', 'Divya Joshi', 'HR', 'HRBP', 'divya.joshi@corp.example.com', '+1 (555) 067-3995', '119000', 'HRBP', '7250', '2015-12-04', '36', 'Kochi, KL');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('100', 'Rahul Sharma', 'Sales', 'Sr AE', 'rahul.sharma@corp.example.com', '+1 (555) 033-7988', '82000', 'Sr AE', '4250', '2020-09-24', '118', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('101', 'Sneha Kulkarni', 'Business', 'Manager', 'sneha.kulkarni@corp.example.com', '+1 (555) 086-4526', '141000', 'Manager', '1250', '2020-02-25', '69', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('102', 'Aarav Singh', 'HR', 'HR Partner', 'aarav.singh@corp.example.com', '+1 (555) 062-8004', '90500', 'HR Partner', '5750', '2019-03-03', '5', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('103', 'Raj Chauhan', 'Sales', 'AE', 'raj.chauhan@corp.example.com', '+1 (555) 021-4820', '83000', 'AE', '1000', '2016-03-17', '24', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('104', 'Dev Joshi', 'Business', 'Director', 'dev.joshi@corp.example.com', '+1 (555) 084-6046', '130500', 'Director', '2500', '2016-07-10', '20', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('105', 'Kavya Rao', 'Sales', 'Sales Manager', 'kavya.rao@corp.example.com', '+1 (555) 080-5419', '100000', 'Sales Manager', '6000', '2020-06-06', '38', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('106', 'Sam Bose', 'Business', 'Manager', 'sam.bose@corp.example.com', '+1 (555) 042-3777', '85000', 'Manager', '2750', '2021-12-07', '22', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('107', 'Leela Singh', 'Business', 'Analyst', 'leela.singh@corp.example.com', '+1 (555) 078-3033', '94500', 'Analyst', '7500', '2018-01-05', '97', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('108', 'Vivaan Chauhan', 'Finance', 'Controller', 'vivaan.chauhan@corp.example.com', '+1 (555) 085-8595', '101830', 'Controller', '7500', '2017-11-17', '14', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('109', 'Meera Iyer', 'Tech', 'SRE', 'meera.iyer@corp.example.com', '+1 (555) 039-5912', '102500', 'SRE', '3250', '2024-10-24', '111', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('110', 'Meera Sharma', 'Tech', 'SRE', 'meera.sharma@corp.example.com', '+1 (555) 015-0893', '150500', 'SRE', '11250', '2022-11-03', '15', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('111', 'Meera Gupta', 'Sales', 'AE', 'meera.gupta@corp.example.com', '+1 (555) 011-9405', '91000', 'AE', '250', '2022-05-30', '1', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('112', 'Riya Chauhan', 'Sales', 'Sr AE', 'riya.chauhan@corp.example.com', '+1 (555) 033-0841', '87000', 'Sr AE', '1750', '2023-10-31', '40', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('113', 'Divya Chauhan', 'HR', 'HR Partner', 'divya.chauhan@corp.example.com', '+1 (555) 061-8056', '69000', 'HR Partner', '2250', '2017-03-27', '79', 'Pune, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('114', 'Kabir Gupta', 'Business', 'Analyst', 'kabir.gupta@corp.example.com', '+1 (555) 041-1940', '141000', 'Analyst', '11500', '2020-10-11', '49', 'Noida, UP');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('115', 'Vikram Pillai', 'Tech', 'Security Analyst', 'vikram.pillai@corp.example.com', '+1 (555) 067-7253', '118000', 'Security Analyst', '6250', '2016-01-07', '20', 'Hyderabad, TS');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('116', 'Divya Pillai', 'Business', 'Director', 'divya.pillai@corp.example.com', '+1 (555) 089-0986', '148000', 'Director', '11250', '2024-05-02', '41', 'Mumbai, MH');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('117', 'Leela Iyer', 'Tech', 'Senior Engineer', 'leela.iyer@corp.example.com', '+1 (555) 043-1330', '100000', 'Senior Engineer', '8250', '2022-06-04', '111', 'Bengaluru, KA');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('118', 'Isha Reddy', 'HR', 'HR Partner', 'isha.reddy@corp.example.com', '+1 (555) 010-6693', '117500', 'HR Partner', '3750', '2016-02-16', '32', 'Chennai, TN');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('119', 'Meera Patel', 'Tech', 'SRE', 'meera.patel@corp.example.com', '+1 (555) 046-7438', '89000', 'SRE', '2250', '2018-08-20', '107', 'Gurugram, HR');
INSERT INTO employees (id, name, department, role, email, phone, salary, designation, bonus, join_date, manager_id, address) VALUES ('120', 'Sara Kulkarni', 'Finance', 'Accountant', 'sara.kulkarni@corp.example.com', '+1 (555) 024-8922', '98369', 'Accountant', '6500', '2018-08-06', '38', 'Pune, MH');
INSERT INTO departments (id, name, manager) VALUES ('0', 'HR', 'Raj Gupta');
INSERT INTO departments (id, name, manager) VALUES ('1', 'Tech', 'Sara Kulkarni');
INSERT INTO departments (id, name, manager) VALUES ('2', 'Business', 'Karan Gupta');
INSERT INTO departments (id, name, manager) VALUES ('3', 'Finance', 'Rohan Patel');
INSERT INTO departments (id, name, manager) VALUES ('4', 'Sales', 'Ananya Das');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('1', 'Leave Policy', 'Leave Policy (HR)
=================
Employees earn 24 days of paid leave per year. Unused leave up to 6 days may be
carried forward. Sick leave requires a medical note beyond 3 continuous days.
Maternity leave is 26 weeks; paternity leave is 10 working days. Apply in the
HR portal at least 7 days in advance for planned leave.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/leave_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('2', 'Compensation Confidentiality', 'Compensation Confidentiality Policy (HR)
========================================
Salary information is confidential. It is shared strictly on a need-to-know
basis: HR partners and the executive team. Individual salaries must never be
discussed in public channels or exposed to other departments. Compensation data
is processed only for payroll and legal purposes (DPDP Act 2023, purpose
limitation). Any suspected leak must be reported to security within 24 hours.', 'Hr', 'Confidential', 'L3', 'hr_docs', 'data/docs/hr_docs/comp_confidentiality.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('3', 'Work From Home Policy', 'Work-From-Home Policy (Tech)
============================
Engineers may work from home up to 3 days per week. Core collaboration hours
are 11:00-15:00 IST. Fully remote arrangements require CTO approval and are
reviewed every 6 months. Home-office stipend is INR 15,000 per year, paid with
the March salary cycle.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/wfh_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('4', 'Secure Coding Standard', 'Secure Coding Standard (Tech)
=============================
All production code must pass SAST and secret scanning before merge. Secrets
belong in the vault, never in source. Every API endpoint must enforce
authentication and role-based authorization server-side. Logs must not contain
personal data. Dependencies are pinned and scanned weekly.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/secure_coding.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('5', 'Board Bonus Memo', 'Board Bonus Summary FY26 (Executive only)
=========================================
Approved executive bonus pool for FY26:
- Meera Nair (CEO): $2,400,000
- James Dsouza (CFO): $1,700,000
- Anita Rao (CTO): $1,600,000
Distribution is handled by the compensation committee. These figures are
board-confidential until the annual filing.', 'Executive', 'Restricted', 'L5', 'exec_docs', 'data/docs/exec_docs/board_bonus.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('6', 'Employee Handbook', '
Employee Handbook (HR)
======================
Welcome to the company. Every employee receives a grade band, a reporting
manager and an annual development plan. The handbook covers working hours,
dress norms, office facilities and the exit process. Notice periods are 30
days for individual contributors and 60 days for leads and managers.
Employees are expected to complete mandatory compliance training within 30
days of joining and once every year after that.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/employee_handbook.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('7', 'Code of Conduct', '
Code of Conduct (HR)
====================
We act with integrity toward colleagues, customers and partners. Harassment,
discrimination and retaliation are zero-tolerance offences. Conflicts of
interest must be declared to your manager and the compliance team. Intellectual
property created during employment belongs to the company. Violations are
handled by the ethics committee with a documented, appealable process.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/code_of_conduct.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('8', 'Benefits Overview', '
Benefits Overview (HR)
======================
Full-time employees are covered by the group medical plan, term life cover and
accident insurance from day one. The wellness allowance reimburses gym or
yoga memberships up to the annual cap. Learning and certification costs are
reimbursed on manager approval. Counseling sessions through the employee
assistance program are free and strictly confidential.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/benefits_overview.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('9', 'Parental Leave', '
Parental Leave (HR)
===================
Birth mothers receive 26 weeks of paid leave, extendable by 8 weeks unpaid.
Non-birth parents receive 10 working days, usable within 6 months of birth.
Adoptive parents of a child under 12 months receive 12 weeks. Flexible
return-to-work offers reduced hours for the first month after a long leave.
Managers may not deny statutory parental leave under any circumstance.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/parental_leave.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('10', 'Grievance Procedure', '
Grievance Procedure (HR)
========================
Raise concerns first with your reporting manager, unless the concern involves
that manager. The HR partner acknowledges every grievance within 2 working
days and closes it, with a written outcome, within 21 days. Sexual harassment
complaints follow the POSH committee process, which runs independently.
Retaliation against a complainant is itself a conduct violation.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/grievance_procedure.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('11', 'Referral Policy', '
Referral Policy (HR)
====================
Employees earn a referral award when a referred candidate completes 90 days
in role. Referrals for business and engineering roles pay one tier; critical
and leadership roles pay a higher tier. Employees may not refer close family
members or anyone in their own reporting chain. The award is paid in the
next monthly cycle after the qualifying date.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/referral_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('12', 'Attendance Policy', '
Attendance Policy (HR)
======================
Standard office hours are 09:30 to 18:15 with a flexible start window.
Attendance is tracked for compliance, not micro-management: regularisation
requests must be filed within 7 days. Three unregularised absence instances
in a quarter trigger a manager conversation. Chronic irregularity may affect
appraisal ratings but never statutory entitlements.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/attendance_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('13', 'Workplace Safety', '
Workplace Safety (HR)
=====================
Emergency exits, assembly points and first-aid kits are marked on every floor.
Fire drills run twice a year and participation is mandatory. Report any hazard
through the safety portal; reports are triaged within one working day. The
facility team maintains CCTV for safety only, and footage retention is 30
days under the privacy policy.', 'Hr', 'Internal', 'L2', 'hr_docs', 'data/docs/hr_docs/workplace_safety.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('14', 'Deployment Runbook', '
Deployment Runbook (Tech)
=========================
Production deploys go through the blue-green pipeline with automated rollback
on health-check failure. Every change needs a reviewed pull request, a passing
CI gate and a linked ticket. Deploys are frozen during the weekend on-call
window unless the incident commander approves. Post-deploy, watch error rate
and p99 latency for 30 minutes before closing the change.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/deployment_runbook.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('15', 'Incident Response Plan', '
Incident Response Plan (Tech)
=============================
Severity 1 means customer-impacting outage or suspected data breach: page the
on-call, open a war room and notify the security duty officer within 15
minutes. Contain first, eradicate second, then recover and verify. Every Sev1
gets a blameless post-mortem within 5 working days with tracked action items.
Regulatory notification decisions are made by the security council, not by
individual engineers.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/incident_response.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('16', 'Architecture Overview', '
Architecture Overview (Tech)
============================
The platform runs as microservices behind an API gateway, with Kafka for event
streaming and PostgreSQL as the primary store. Services communicate over mTLS
with workload identities issued at deploy time. The AI assistant is isolated
in its own security zone and reaches data only through the governance
pipeline. Capacity headroom is reviewed monthly against the growth forecast.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/architecture_overview.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('17', 'On-call Handbook', '
On-call Handbook (Tech)
=======================
The rotation is weekly, primary and shadow, handed over every Monday with a
written summary of open risks. Acknowledge pages within 5 minutes; escalate
to the secondary after 15 without progress. Keep the runbook links updated
before your rotation starts, not during an incident. Compensation for weekend
on-call follows the finance policy on additional duty hours.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/oncall_handbook.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('18', 'Access Management Standard', '
Access Management Standard (Tech)
=================================
Access is granted by role, reviewed quarterly, and revoked on the day of role
change. Production access requires hardware-token MFA and just-in-time
elevation with an expiry. Break-glass credentials are sealed, monitored and
rotated after every use. No human or service account may bypass the central
audit log for any reason.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/access_management.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('19', 'Disaster Recovery and Backup', '
Disaster Recovery and Backup (Tech)
===================================
Backups are encrypted, incremental and tested by a quarterly restore drill.
Recovery point objective is 15 minutes for tier-1 stores; recovery time
objective is 60 minutes. The DR site runs in a separate region with
independent credentials. Restore results are signed off by the platform lead
and filed with the audit team.', 'Tech', 'Internal', 'L2', 'tech_docs', 'data/docs/tech_docs/dr_backup_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('20', 'Q1 Strategy', '
Q1 Strategy (Business)
======================
Q1 focuses on expansion in mid-market accounts and a bundled offering for the
manufacturing vertical. The pipeline target grows by a double-digit percentage
over the previous quarter, weighted toward multi-year contracts. Partner-led
deals get priority enablement support. This plan is commercially sensitive:
share externally only under NDA and never through public channels.', 'Business', 'Confidential', 'L3', 'business_docs', 'data/docs/business_docs/q1_strategy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('21', 'Competitor Analysis', '
Competitor Analysis (Business)
==============================
Three competitors dominate the mid-market segment; two are competing on
price, one on integration depth. Their public roadmaps suggest a growing push
into compliance automation, which validates our differentiated controls.
Win rates improved after the packaging change introduced last year. Position
against the price-led players by quantifying total cost of ownership rather
than discounting.', 'Business', 'Confidential', 'L3', 'business_docs', 'data/docs/business_docs/competitor_analysis.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('22', 'Pricing Policy', '
Pricing Policy (Business)
=========================
List prices are published per seat with volume tiers at fixed breakpoints.
Discounts above the standard band need regional sales-director approval, and
above the extended band need the pricing committee. Evaluation licences run
for a fixed term and convert only through a signed order form. Currency and
tax treatment follow the finance booking rules for each region.', 'Business', 'Confidential', 'L3', 'business_docs', 'data/docs/business_docs/pricing_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('23', 'Sales Playbook', '
Sales Playbook (Business)
=========================
Qualify every opportunity on need, authority, timing and fit before demoing.
The standard cycle is discovery, technical validation, commercial review and
procurement. Use the CRM stage definitions exactly; forecasting accuracy is
a shared team metric. Escalate security-questionnaire blockers to the
pre-sales solutions team instead of promising custom work.', 'Business', 'Internal', 'L2', 'business_docs', 'data/docs/business_docs/sales_playbook.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('24', 'Partner Policy', '
Partner Policy (Business)
=========================
Partners are tiered by certified skills and sourced revenue. Deal
registration protects the first registered partner for a fixed window.
Partners may not subcontract delivery of security-critical workloads. Joint
marketing requires brand review and must not imply exclusive rights. Tier
reviews run twice a year on objective criteria.', 'Business', 'Internal', 'L2', 'business_docs', 'data/docs/business_docs/partner_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('25', 'Market Research 2026', '
Market Research 2026 (Business)
===============================
Demand for governed AI assistants keeps accelerating as regulators publish
enterprise guidance. Buyers now shortlist vendors on auditability, data
residency and role-based access rather than model benchmarks. Budget owners
consolidate point tools into platform purchases. The mid-market remains the
fastest-growing segment for the next four quarters.', 'Business', 'Internal', 'L2', 'business_docs', 'data/docs/business_docs/market_research_2026.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('26', 'FY27 Budget Summary', '
FY27 Budget Summary (Finance)
=============================
The FY27 plan prioritises platform reliability, security tooling and compliance
certification. Headcount growth is front-loaded in engineering, flat in
general and administrative functions. Cloud spend carries a committed-use
discount negotiated last quarter. Variance above the approved band requires
finance-council sign-off before commitment.', 'Finance', 'Confidential', 'L3', 'finance_docs', 'data/docs/finance_docs/fy27_budget_summary.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('27', 'Expense Policy', '
Expense Policy (Finance)
========================
Submit expenses within 30 days of purchase with itemised receipts. Domestic
travel books economy; international long-haul books premium economy with
pre-approval. Client entertainment needs a business purpose and attendee
list. Cash advances settle with the final report; unresolved advances move
to payroll deduction after due notice.', 'Finance', 'Internal', 'L2', 'finance_docs', 'data/docs/finance_docs/expense_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('28', 'Procurement Policy', '
Procurement Policy (Finance)
============================
Purchases above the threshold need three comparative quotes and a signed
purchase order before work starts. Vendor onboarding includes sanctions
screening and a data-protection review when personal data is involved.
Renewals are reviewed 90 days ahead for value and utilisation. No team may
engage a vendor informally to bypass the controls.', 'Finance', 'Internal', 'L2', 'finance_docs', 'data/docs/finance_docs/procurement_policy.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('29', 'Cashflow Forecast Q1', '
Cashflow Forecast Q1 (Finance)
==============================
Collections concentrate in the last month of the quarter, so the treasury
buffer covers the early-weeks trough. Vendor payment runs are scheduled to
protect the minimum liquidity band. The forecast assumes no early debt
reduction this quarter. Treasury movements above the delegated limit need
dual authorisation by the finance lead and the CFO office.', 'Finance', 'Confidential', 'L3', 'finance_docs', 'data/docs/finance_docs/cashflow_forecast_q1.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('30', 'Board Minutes Q1', '
Board Minutes Q1 (Executive only)
=================================
The board reviewed the annual filing calendar and the audit plan. Risk
appetite was reaffirmed, with explicit attention to third-party and AI
governance exposure. The compensation committee confirmed the executive
reward outcomes recorded separately in the restricted annex. Minutes are
distributed to directors only and embargoed until the next meeting.', 'Executive', 'Restricted', 'L5', 'exec_docs', 'data/docs/exec_docs/board_minutes_q1.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('31', 'MA Pipeline', '
M&A Pipeline (Executive only)
=============================
Two targets are in active diligence: a regional services firm and a
compliance-automation startup. The working group includes corporate
development, legal and information security. Deal terms, valuations and
integration drafts are board-restricted until signing. Leaks to press or
staff would be a material governance breach with disciplinary consequence.', 'Executive', 'Restricted', 'L5', 'exec_docs', 'data/docs/exec_docs/ma_pipeline.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('32', 'Succession Plan', '
Succession Plan (Executive only)
================================
Every C-level seat has a named ready-now or ready-soon successor with a
development plan. Emergency succession covers absence within 48 hours.
The plan is refreshed after each board cycle and held by the CHRO and the
board secretary. Contents are personal-data sensitive and must not be
summarised outside the restricted distribution.', 'Executive', 'Restricted', 'L5', 'exec_docs', 'data/docs/exec_docs/succession_plan.txt');
INSERT INTO documents (doc_id, title, content, department, sensitivity, min_clearance, namespace, file_path) VALUES ('33', 'Investor Update', '
Investor Update (Executive only)
================================
The quarterly investor letter drafts the narrative before the earnings call:
growth, margin discipline and governance investments. Forward statements
follow the disclosure policy and legal review. Undisclosed material
information must never reach analysts, press or internal chat. The final
version is published by the investor-relations office only.', 'Executive', 'Restricted', 'L5', 'exec_docs', 'data/docs/exec_docs/investor_update.txt');
-- ============ executives.db ============
CREATE TABLE executives (
            id INTEGER PRIMARY KEY, name TEXT, role TEXT, bonus INTEGER,
            annual_salary INTEGER, stock_options INTEGER,
            performance_bonus INTEGER, contract_terms TEXT);
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('1', 'Meera Nair', 'CEO', '2400000', '24000000', '520000', '2400000', '3-year term, 12-month notice, clawback applies');
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('2', 'James Dsouza', 'CFO', '1700000', '16000000', '310000', '1700000', '3-year term, 6-month notice, audit committee sign-off');
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('3', 'Anita Rao', 'CTO', '1600000', '15000000', '290000', '1600000', '3-year term, 6-month notice, IP assignment');
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('4', 'Ravi Menon', 'COO', '1200000', '11500000', '210000', '1200000', '2-year term, 6-month notice');
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('5', 'Sara Khan', 'CISO', '950000', '9200000', '150000', '950000', '2-year term, 3-month notice, security clearance required');
INSERT INTO executives (id, name, role, bonus, annual_salary, stock_options, performance_bonus, contract_terms) VALUES ('6', 'Tom Verghese', 'CHRO', '800000', '8100000', '120000', '800000', '2-year term, 3-month notice');
COMMIT;
