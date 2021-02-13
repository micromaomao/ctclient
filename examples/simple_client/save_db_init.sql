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
    'https://ct.googleapis.com/logs/xenon2020/',
    x'3059301306072a8648ce3d020106082a8648ce3d03010703420004654ef956a8f2cd24e01592809d683541e61f14521165330aeeade459666c98785076b0589c7459dce038914794c7424dfb15fe75282dd6bbaa521865ee33af9b',
    0,
    x'0000000000000000000000000000000000000000000000000000000000000000'
);

CREATE TABLE "found_my_certs" (
    "log_id" INTEGER NOT NULL REFERENCES "ctlogs"("id"),
    "x509_der" BLOB NOT NULL,
    "ca_der" BLOB NOT NULL
);
