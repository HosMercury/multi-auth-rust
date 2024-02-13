CREATE TABLE IF NOT EXISTS groups (
    id SERIAl PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAl PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users_groups (
    user_id UUID REFERENCES users(id),
    group_id INTEGER REFERENCES groups(id),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS groups_permissions (
    group_id INTEGER REFERENCES groups(id),
    permission_id INTEGER REFERENCES permissions(id),
    primary key (group_id, permission_id)
);

----------------- Seeding --------------
insert INTO groups (name)
VALUES ('users'),('admins');

insert into permissions (name)
VALUES ('dashboard.read'), ('restricted.read');

INSERT INTO groups_permissions (group_id, permission_id)
VALUES (
    (SELECT id FROM groups WHERE name = 'users'),
    (SELECT id FROM permissions WHERE name = 'dashboard.read')
), (
    (SELECT id FROM groups WHERE name = 'admins'),
    (SELECT id FROM permissions WHERE name = 'dashboard.read')
);

INSERT INTO users_groups (user_id, group_id)
VALUES (
    (SELECT id FROM users WHERE username = 'ferris'),
    (select id FROM groups WHERE name = 'users')
), (
    (SELECT id FROM users WHERE username = 'admin'),
    (SELECT id FROM groups WHERE name = 'users')
), (
    (SELECT id FROM users WHERE username = 'admin'),
    (SELECT id FROM groups WHERE name = 'admins')
);



