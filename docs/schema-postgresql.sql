-- Generated from SQLAlchemy metadata; use init-db for application setup.


CREATE TABLE "user" (
	id SERIAL NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	phone_cipher TEXT, 
	PRIMARY KEY (id), 
	CHECK (role in ('student','teacher','admin')), 
	UNIQUE (email)
)

;


CREATE TABLE attempt (
	id SERIAL NOT NULL, 
	user_id INTEGER NOT NULL, 
	score INTEGER NOT NULL, 
	level VARCHAR(10) NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	synthetic BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	CHECK (score >= 0 and score <= 100), 
	FOREIGN KEY(user_id) REFERENCES "user" (id)
)

;


CREATE TABLE audit (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	action VARCHAR(80) NOT NULL, 
	created TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES "user" (id)
)

;

CREATE INDEX ix_audit_created ON audit (created);


CREATE TABLE course (
	id SERIAL NOT NULL, 
	title VARCHAR(150) NOT NULL, 
	level VARCHAR(10) NOT NULL, 
	teacher_id INTEGER NOT NULL, 
	content TEXT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(teacher_id) REFERENCES "user" (id)
)

;


CREATE TABLE login_session (
	id VARCHAR(64) NOT NULL, 
	user_id INTEGER NOT NULL, 
	expires TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES "user" (id)
)

;


CREATE TABLE enrollment (
	id SERIAL NOT NULL, 
	user_id INTEGER NOT NULL, 
	course_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (user_id, course_id), 
	FOREIGN KEY(user_id) REFERENCES "user" (id), 
	FOREIGN KEY(course_id) REFERENCES course (id)
)

;


CREATE TABLE homework (
	id SERIAL NOT NULL, 
	course_id INTEGER NOT NULL, 
	title VARCHAR(150) NOT NULL, 
	body TEXT NOT NULL, 
	due TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(course_id) REFERENCES course (id)
)

;


CREATE TABLE lesson (
	id SERIAL NOT NULL, 
	course_id INTEGER NOT NULL, 
	starts TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	room VARCHAR(100) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(course_id) REFERENCES course (id)
)

;


CREATE TABLE submission (
	id SERIAL NOT NULL, 
	homework_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	answer TEXT NOT NULL, 
	grade INTEGER, 
	feedback TEXT, 
	PRIMARY KEY (id), 
	UNIQUE (homework_id, user_id), 
	CHECK (grade >= 0 and grade <= 100), 
	FOREIGN KEY(homework_id) REFERENCES homework (id), 
	FOREIGN KEY(user_id) REFERENCES "user" (id)
)

;