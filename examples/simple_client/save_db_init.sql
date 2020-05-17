CREATE TABLE "ctlogs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"url"	TEXT NOT NULL UNIQUE,
	"pub_key"	BLOB NOT NULL,
	"checked_tree_size"	INTEGER NOT NULL,
	"checked_tree_head"	BLOB NOT NULL
);

CREATE TABLE "received_signed_tree_heads" (
    "log_id" INTEGER NOT NULL REFERENCES "ctlogs"("id"),
	"tree_size"	INTEGER NOT NULL,
	"timestamp"	INTEGER NOT NULL,
	"tree_hash"	BLOB NOT NULL,
	"signature"	BLOB NOT NULL
);

CREATE INDEX sth_tree_size_idx ON "received_signed_tree_heads" ("log_id", "tree_size");

INSERT INTO "ctlogs" (id, url, pub_key, checked_tree_size, checked_tree_head) VALUES (
    0,
    'https://ct.googleapis.com/logs/argon2020/',
    x'3059301306072a8648ce3d020106082a8648ce3d03010703420004e93c76a75c8a638d35e4dc8862f76b937e9eb34b80735cc0e0f43e4c6458fb766351321863d5b2bbedeaff5e3b246e2f35528bb4359aad9c15a86920ea5018cc',
    0,
    x'0000000000000000000000000000000000000000000000000000000000000000'
);
