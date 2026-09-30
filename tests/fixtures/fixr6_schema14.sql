PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO metadata VALUES('schema_version','14');
INSERT INTO metadata VALUES('schema_layout','versioned');
CREATE TABLE libraries (
    id TEXT PRIMARY KEY COLLATE NOCASE,
    name TEXT NOT NULL,
    source_root TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at TEXT NOT NULL,
    retired_at TEXT
, last_scan_files INTEGER, last_scan_bytes INTEGER, last_scanned_at TEXT);
INSERT INTO libraries VALUES('LIB1','Sanitized library LIB1','/legacy/source','active','2026-08-22T06:20:35+00:00',NULL,NULL,NULL,NULL);
CREATE TABLE tapes (
    id TEXT PRIMARY KEY COLLATE NOCASE,
    volume_serial TEXT NOT NULL,
    volume_label TEXT NOT NULL,
    filesystem TEXT NOT NULL,
    mount_hint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
, cassette_number TEXT);
INSERT INTO tapes VALUES('TAPE01','SERIAL01','TAPE01','LTFS','/synthetic/mount','active','2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00','TAPE01');
INSERT INTO tapes VALUES('TAPE02','SERIAL02','TAPE02','LTFS','/synthetic/mount','active','2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00','TAPE02');
INSERT INTO tapes VALUES('TAPE03','SERIAL03','TAPE03','LTFS','/synthetic/mount','active','2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00','TAPE03');
INSERT INTO tapes VALUES('TAPE04','SERIAL04','TAPE04','LTFS','/synthetic/mount','active','2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00','TAPE04');
CREATE TABLE blocks (
    id TEXT PRIMARY KEY,
    library_id TEXT NOT NULL REFERENCES libraries(id),
    tape_id TEXT NOT NULL REFERENCES tapes(id),
    tape_relative_root TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('copying', 'completed', 'failed')),
    visible INTEGER NOT NULL DEFAULT 1 CHECK(visible IN (0, 1)),
    planned_files INTEGER NOT NULL,
    planned_bytes INTEGER NOT NULL,
    copied_files INTEGER NOT NULL DEFAULT 0,
    copied_bytes INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT
);
INSERT INTO blocks VALUES('BLOCK01-01','LIB1','TAPE01','archive','completed',1,1,1,1,1,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK01-02','LIB1','TAPE01','archive','completed',1,1,1,1,1,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK02-01','LIB1','TAPE02','archive','completed',1,1,2,1,2,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK02-02','LIB1','TAPE02','archive','completed',1,1,2,1,2,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK03-01','LIB1','TAPE03','archive','completed',1,1,3,1,3,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK03-02','LIB1','TAPE03','archive','completed',1,1,3,1,3,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK04-01','LIB1','TAPE04','archive','completed',1,1,4,1,4,'2026-08-22T00:01:10+00:00','2026-08-22T06:20:35.399298+00:00',NULL);
INSERT INTO blocks VALUES('BLOCK04-02','LIB1','TAPE04','archive','completed',1,1,4,1,4,'2026-08-22T00:01:10+00:00','2026-08-22T06:20:35.399298+00:00',NULL);
CREATE TABLE file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    library_id TEXT NOT NULL REFERENCES libraries(id),
    block_id TEXT NOT NULL REFERENCES blocks(id),
    tape_id TEXT NOT NULL REFERENCES tapes(id),
    relative_path TEXT NOT NULL,
    tape_relative_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    copied_at TEXT NOT NULL,
    visible INTEGER NOT NULL DEFAULT 1 CHECK(visible IN (0, 1))
, parent_path TEXT NOT NULL DEFAULT '', file_name TEXT NOT NULL DEFAULT '', created_ns INTEGER, accessed_ns INTEGER, source_mode INTEGER, windows_attributes INTEGER, owner_name TEXT, owner_sid TEXT, security_descriptor TEXT, alternate_streams_json TEXT NOT NULL DEFAULT '[]', metadata_state TEXT NOT NULL DEFAULT 'legacy', metadata_error TEXT);
INSERT INTO file_versions VALUES(1,'LIB1','BLOCK01-01','TAPE01','cassette-1/file-1.bin','archive/files/cassette-1/file-1.bin',1,1,'0000000000000000000000000000000000000000000000000000000000000003','2026-08-22T06:20:35+00:00',1,'cassette-1','file-1.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(2,'LIB1','BLOCK01-02','TAPE01','cassette-1/file-2.bin','archive/files/cassette-1/file-2.bin',1,2,'0000000000000000000000000000000000000000000000000000000000000004','2026-08-22T06:20:35+00:00',1,'cassette-1','file-2.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(3,'LIB1','BLOCK02-01','TAPE02','cassette-2/file-1.bin','archive/files/cassette-2/file-1.bin',2,2,'0000000000000000000000000000000000000000000000000000000000000005','2026-08-22T06:20:35+00:00',1,'cassette-2','file-1.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(4,'LIB1','BLOCK02-02','TAPE02','cassette-2/file-2.bin','archive/files/cassette-2/file-2.bin',2,3,'0000000000000000000000000000000000000000000000000000000000000006','2026-08-22T06:20:35+00:00',1,'cassette-2','file-2.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(5,'LIB1','BLOCK03-01','TAPE03','cassette-3/file-1.bin','archive/files/cassette-3/file-1.bin',3,3,'0000000000000000000000000000000000000000000000000000000000000007','2026-08-22T06:20:35+00:00',1,'cassette-3','file-1.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(6,'LIB1','BLOCK03-02','TAPE03','cassette-3/file-2.bin','archive/files/cassette-3/file-2.bin',3,4,'0000000000000000000000000000000000000000000000000000000000000008','2026-08-22T06:20:35+00:00',1,'cassette-3','file-2.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(7,'LIB1','BLOCK04-01','TAPE04','cassette-4/file-1.bin','archive/files/cassette-4/file-1.bin',4,4,'00000000000000000000000000000000000000000000000000000000000001f5','2026-08-22T00:01:20+00:00',1,'cassette-4','file-1.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
INSERT INTO file_versions VALUES(8,'LIB1','BLOCK04-02','TAPE04','cassette-4/file-2.bin','archive/files/cassette-4/file-2.bin',4,5,'00000000000000000000000000000000000000000000000000000000000001f6','2026-08-22T00:01:20+00:00',1,'cassette-4','file-2.bin',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[]','legacy',NULL);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
INSERT INTO events VALUES(1,'2026-08-22T06:20:35+00:00','catalog.migrate','{"cassette_number_default": "tape_id", "from_version": 1, "to_version": 2}');
INSERT INTO events VALUES(2,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 2, "to_version": 3}');
INSERT INTO events VALUES(3,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 3, "to_version": 4}');
INSERT INTO events VALUES(4,'2026-08-22T06:20:35+00:00','catalog.migrate','{"file_versions_backfilled": 0, "from_version": 4, "to_version": 5}');
INSERT INTO events VALUES(5,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 5, "to_version": 6}');
INSERT INTO events VALUES(6,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 6, "legacy_force_format": false, "to_version": 7}');
INSERT INTO events VALUES(7,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 7, "job_names_default": "job_id", "to_version": 8}');
INSERT INTO events VALUES(8,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 8, "legacy_media_key": "LTO-6", "to_version": 9}');
INSERT INTO events VALUES(9,'2026-08-22T06:20:35+00:00','catalog.migrate','{"cassette_operation": "format", "from_version": 9, "to_version": 10}');
INSERT INTO events VALUES(10,'2026-08-22T06:20:35+00:00','catalog.migrate','{"cassette_manifests": true, "from_version": 10, "to_version": 11}');
INSERT INTO events VALUES(11,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 11, "registered_tape_reuse": false, "to_version": 12}');
INSERT INTO events VALUES(12,'2026-08-22T06:20:35+00:00','catalog.migrate','{"from_version": 12, "ltfs_identity": "volume_label", "to_version": 13, "win32_volume_serial": "diagnostic"}');
INSERT INTO events VALUES(13,'2026-08-22T06:20:35+00:00','library.add','{"library_id": "LIB1", "source_root": "/tmp/tmpx__xqc1l/source-lib1"}');
INSERT INTO events VALUES(14,'2026-08-22T06:20:35+00:00','automatic_job.create','{"allow_registered_reuse": false, "device_name": "synthetic-drive", "force_format": true, "job_id": "JOB-MIGRATION", "labels": ["TAPE01", "TAPE02", "TAPE03", "TAPE04", "TAPE05", "TAPE06", "TAPE07", "TAPE08", "TAPE09", "TAPE10", "TAPE11", "TAPE12", "TAPE13", "TAPE14", "TAPE15", "TAPE16", "TAPE17", "TAPE18", "TAPE19", "TAPE20"], "library_id": "LIB1", "library_ids": ["LIB1"], "media_key": "LTO-6", "mount_path": "/synthetic/mount"}');
INSERT INTO events VALUES(15,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 2, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 1}');
INSERT INTO events VALUES(16,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 4, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 2}');
INSERT INTO events VALUES(17,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 6, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 3}');
INSERT INTO events VALUES(18,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 8, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 4}');
INSERT INTO events VALUES(19,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 10, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 5}');
INSERT INTO events VALUES(20,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 12, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 6}');
INSERT INTO events VALUES(21,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 14, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 7}');
INSERT INTO events VALUES(22,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 16, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 8}');
INSERT INTO events VALUES(23,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 18, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 9}');
INSERT INTO events VALUES(24,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 20, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 10}');
INSERT INTO events VALUES(25,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 22, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 11}');
INSERT INTO events VALUES(26,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 24, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 12}');
INSERT INTO events VALUES(27,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 26, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 13}');
INSERT INTO events VALUES(28,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 28, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 14}');
INSERT INTO events VALUES(29,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 30, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 15}');
INSERT INTO events VALUES(30,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 32, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 16}');
INSERT INTO events VALUES(31,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 34, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 17}');
INSERT INTO events VALUES(32,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 36, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 18}');
INSERT INTO events VALUES(33,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 38, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 19}');
INSERT INTO events VALUES(34,'2026-08-22T06:20:35+00:00','automatic_cassette.manifest','{"bytes": 40, "files": 2, "job_id": "JOB-MIGRATION", "sequence": 20}');
INSERT INTO events VALUES(35,'2026-08-22T06:20:35+00:00','tape.register','{"cassette_number": "TAPE01", "serial": "SERIAL01", "tape_id": "TAPE01"}');
INSERT INTO events VALUES(36,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK01-01", "library_id": "LIB1", "planned_bytes": 1, "planned_files": 1, "tape_id": "TAPE01"}');
INSERT INTO events VALUES(37,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK01-01"}');
INSERT INTO events VALUES(38,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK01-02", "library_id": "LIB1", "planned_bytes": 1, "planned_files": 1, "tape_id": "TAPE01"}');
INSERT INTO events VALUES(39,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK01-02"}');
INSERT INTO events VALUES(40,'2026-08-22T06:20:35+00:00','automatic_cassette.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 1, "status": "completed"}');
INSERT INTO events VALUES(41,'2026-08-22T06:20:35+00:00','tape.register','{"cassette_number": "TAPE02", "serial": "SERIAL02", "tape_id": "TAPE02"}');
INSERT INTO events VALUES(42,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK02-01", "library_id": "LIB1", "planned_bytes": 2, "planned_files": 1, "tape_id": "TAPE02"}');
INSERT INTO events VALUES(43,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK02-01"}');
INSERT INTO events VALUES(44,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK02-02", "library_id": "LIB1", "planned_bytes": 2, "planned_files": 1, "tape_id": "TAPE02"}');
INSERT INTO events VALUES(45,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK02-02"}');
INSERT INTO events VALUES(46,'2026-08-22T06:20:35+00:00','automatic_cassette.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 2, "status": "completed"}');
INSERT INTO events VALUES(47,'2026-08-22T06:20:35+00:00','tape.register','{"cassette_number": "TAPE03", "serial": "SERIAL03", "tape_id": "TAPE03"}');
INSERT INTO events VALUES(48,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK03-01", "library_id": "LIB1", "planned_bytes": 3, "planned_files": 1, "tape_id": "TAPE03"}');
INSERT INTO events VALUES(49,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK03-01"}');
INSERT INTO events VALUES(50,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK03-02", "library_id": "LIB1", "planned_bytes": 3, "planned_files": 1, "tape_id": "TAPE03"}');
INSERT INTO events VALUES(51,'2026-08-22T06:20:35+00:00','block.complete','{"block_id": "BLOCK03-02"}');
INSERT INTO events VALUES(52,'2026-08-22T06:20:35+00:00','automatic_cassette.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 3, "status": "completed"}');
INSERT INTO events VALUES(53,'2026-08-22T06:20:35+00:00','automatic_job.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 4, "status": "waiting_media"}');
INSERT INTO events VALUES(54,'2026-08-22T06:20:35+00:00','tape.register','{"cassette_number": "TAPE04", "serial": "SERIAL04", "tape_id": "TAPE04"}');
INSERT INTO events VALUES(55,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK04-01", "library_id": "LIB1", "planned_bytes": 4, "planned_files": 1, "tape_id": "TAPE04"}');
INSERT INTO events VALUES(56,'2026-08-22T06:20:35+00:00','block.start','{"block_id": "BLOCK04-02", "library_id": "LIB1", "planned_bytes": 4, "planned_files": 1, "tape_id": "TAPE04"}');
INSERT INTO events VALUES(57,'2026-08-22T06:20:35+00:00','automatic_cassette.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 4, "status": "committing"}');
INSERT INTO events VALUES(58,'2026-08-22T06:20:35+00:00','automatic_job.state','{"error": null, "job_id": "JOB-MIGRATION", "sequence": 4, "status": "writing"}');
CREATE TABLE IF NOT EXISTS "automatic_jobs" (
                id TEXT PRIMARY KEY COLLATE NOCASE,
                display_name TEXT NOT NULL,
                media_key TEXT NOT NULL DEFAULT 'LTO-6',
                library_id TEXT NOT NULL REFERENCES libraries(id),
                device_name TEXT NOT NULL,
                mount_path TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'planned','pending','waiting_media','identifying_media',
                    'formatting_media','mounting','writing','writing_manifest',
                    'finalizing_index','unmounting','committing','unloading',
                    'paused','completed','failed'
                )),
                current_sequence INTEGER NOT NULL DEFAULT 0,
                total_cassettes INTEGER NOT NULL,
                destructive_confirmed_at TEXT NOT NULL,
                force_format INTEGER NOT NULL DEFAULT 0 CHECK(force_format IN (0, 1)),
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                last_error TEXT
            );
INSERT INTO automatic_jobs VALUES('JOB-MIGRATION','JOB-MIGRATION','LTO-6','LIB1','synthetic-drive','/synthetic/mount','waiting_media',5,20,'2026-08-22T06:20:35+00:00',1,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL,NULL);
CREATE TABLE IF NOT EXISTS "automatic_cassettes" (
                job_id TEXT NOT NULL REFERENCES "automatic_jobs"(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                physical_label TEXT NOT NULL COLLATE NOCASE,
                tape_serial TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'pending','waiting_media','identifying_media','formatting_media',
                    'mounting','writing','writing_manifest','finalizing_index',
                    'unmounting','committing','unloading','paused','completed','failed'
                )),
                tape_id TEXT,
                block_id TEXT,
                planned_files INTEGER NOT NULL,
                planned_bytes INTEGER NOT NULL,
                copied_files INTEGER NOT NULL DEFAULT 0,
                copied_bytes INTEGER NOT NULL DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                operation TEXT NOT NULL DEFAULT 'format'
                    CHECK(operation IN ('format', 'append')),
                reuse_registered INTEGER NOT NULL DEFAULT 0
                    CHECK(reuse_registered IN (0, 1)),
                PRIMARY KEY(job_id, sequence),
                UNIQUE(job_id, physical_label),
                UNIQUE(job_id, tape_serial)
            );
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',1,'TAPE01','SERIAL01','completed','TAPE01','BLOCK01-01,BLOCK01-02',2,2,2,2,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',2,'TAPE02','SERIAL02','completed','TAPE02','BLOCK02-01,BLOCK02-02',2,4,2,4,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',3,'TAPE03','SERIAL03','completed','TAPE03','BLOCK03-01,BLOCK03-02',2,6,2,6,'2026-08-22T06:20:35+00:00','2026-08-22T06:20:35+00:00',NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',4,'TAPE04','SERIAL04','completed','TAPE04','BLOCK04-01,BLOCK04-02',2,8,2,8,'2026-08-22T00:01:00+00:00','2026-08-22T06:20:35.399298+00:00',NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',5,'TAPE05','SERIAL05','pending',NULL,NULL,2,10,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',6,'TAPE06','SERIAL06','pending',NULL,NULL,2,12,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',7,'TAPE07','SERIAL07','pending',NULL,NULL,2,14,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',8,'TAPE08','SERIAL08','pending',NULL,NULL,2,16,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',9,'TAPE09','SERIAL09','pending',NULL,NULL,2,18,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',10,'TAPE10','SERIAL10','pending',NULL,NULL,2,20,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',11,'TAPE11','SERIAL11','pending',NULL,NULL,2,22,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',12,'TAPE12','SERIAL12','pending',NULL,NULL,2,24,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',13,'TAPE13','SERIAL13','pending',NULL,NULL,2,26,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',14,'TAPE14','SERIAL14','pending',NULL,NULL,2,28,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',15,'TAPE15','SERIAL15','pending',NULL,NULL,2,30,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',16,'TAPE16','SERIAL16','pending',NULL,NULL,2,32,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',17,'TAPE17','SERIAL17','pending',NULL,NULL,2,34,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',18,'TAPE18','SERIAL18','pending',NULL,NULL,2,36,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',19,'TAPE19','SERIAL19','pending',NULL,NULL,2,38,0,0,NULL,NULL,NULL,'format',0);
INSERT INTO automatic_cassettes VALUES('JOB-MIGRATION',20,'TAPE20','SERIAL20','pending',NULL,NULL,2,40,0,0,NULL,NULL,NULL,'format',0);
CREATE TABLE IF NOT EXISTS "automatic_job_libraries" (
                job_id TEXT NOT NULL REFERENCES "automatic_jobs"(id) ON DELETE CASCADE,
                library_id TEXT NOT NULL REFERENCES libraries(id),
                sequence INTEGER NOT NULL,
                PRIMARY KEY(job_id, library_id),
                UNIQUE(job_id, sequence)
            );
INSERT INTO automatic_job_libraries VALUES('JOB-MIGRATION','LIB1',1);
CREATE TABLE IF NOT EXISTS "automatic_cassette_items" (
                job_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                item_sequence INTEGER NOT NULL,
                library_id TEXT NOT NULL REFERENCES libraries(id),
                relative_path TEXT NOT NULL COLLATE NOCASE,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                PRIMARY KEY(job_id, sequence, item_sequence),
                UNIQUE(job_id, library_id, relative_path),
                FOREIGN KEY(job_id, sequence)
                    REFERENCES "automatic_cassettes"(job_id, sequence) ON DELETE CASCADE
            );
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',4,1,'LIB1','cassette-4/file-1.bin',4,4);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',4,2,'LIB1','cassette-4/file-2.bin',4,5);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',5,1,'LIB1','cassette-5/file-1.bin',5,5);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',5,2,'LIB1','cassette-5/file-2.bin',5,6);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',6,1,'LIB1','cassette-6/file-1.bin',6,6);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',6,2,'LIB1','cassette-6/file-2.bin',6,7);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',7,1,'LIB1','cassette-7/file-1.bin',7,7);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',7,2,'LIB1','cassette-7/file-2.bin',7,8);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',8,1,'LIB1','cassette-8/file-1.bin',8,8);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',8,2,'LIB1','cassette-8/file-2.bin',8,9);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',9,1,'LIB1','cassette-9/file-1.bin',9,9);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',9,2,'LIB1','cassette-9/file-2.bin',9,10);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',10,1,'LIB1','cassette-10/file-1.bin',10,10);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',10,2,'LIB1','cassette-10/file-2.bin',10,11);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',11,1,'LIB1','cassette-11/file-1.bin',11,11);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',11,2,'LIB1','cassette-11/file-2.bin',11,12);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',12,1,'LIB1','cassette-12/file-1.bin',12,12);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',12,2,'LIB1','cassette-12/file-2.bin',12,13);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',13,1,'LIB1','cassette-13/file-1.bin',13,13);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',13,2,'LIB1','cassette-13/file-2.bin',13,14);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',14,1,'LIB1','cassette-14/file-1.bin',14,14);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',14,2,'LIB1','cassette-14/file-2.bin',14,15);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',15,1,'LIB1','cassette-15/file-1.bin',15,15);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',15,2,'LIB1','cassette-15/file-2.bin',15,16);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',16,1,'LIB1','cassette-16/file-1.bin',16,16);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',16,2,'LIB1','cassette-16/file-2.bin',16,17);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',17,1,'LIB1','cassette-17/file-1.bin',17,17);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',17,2,'LIB1','cassette-17/file-2.bin',17,18);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',18,1,'LIB1','cassette-18/file-1.bin',18,18);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',18,2,'LIB1','cassette-18/file-2.bin',18,19);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',19,1,'LIB1','cassette-19/file-1.bin',19,19);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',19,2,'LIB1','cassette-19/file-2.bin',19,20);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',20,1,'LIB1','cassette-20/file-1.bin',20,20);
INSERT INTO automatic_cassette_items VALUES('JOB-MIGRATION',20,2,'LIB1','cassette-20/file-2.bin',20,21);
CREATE TABLE daemon_operations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'running','succeeded','failed','cancelled','recovery_required'
                )),
                phase TEXT CHECK(phase IS NULL OR phase IN (
                    'identifying_media','formatting_media','mounting','writing',
                    'writing_manifest','finalizing_index','unmounting','committing','unloading'
                )),
                idempotency_key TEXT NOT NULL UNIQUE,
                principal TEXT NOT NULL,
                owner_generation INTEGER NOT NULL,
                job_id TEXT,
                cassette_sequence INTEGER,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                error_class TEXT CHECK(error_class IN (
                    'retryable','operator_required','terminal_safety_failure'
                )),
                error_code TEXT,
                error_message TEXT
            );
INSERT INTO daemon_operations VALUES('operation-4','archive.resume','recovery_required','unloading','resume-4','admin',1,'JOB-MIGRATION',4,'2026-08-22T00:00:05+00:00',NULL,'operator_required','recovery_required','Safe reconciliation is required before another operation.');
CREATE TABLE operation_hardware_targets (
                operation_id TEXT PRIMARY KEY REFERENCES daemon_operations(id),
                mount_path_sha256 TEXT NOT NULL CHECK(length(mount_path_sha256) = 64),
                tape_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(tape_device_identity_sha256) = 64),
                scsi_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(scsi_device_identity_sha256) = 64),
                expected_media_scope_sha256 TEXT NOT NULL
                    CHECK(length(expected_media_scope_sha256) = 64),
                bound_at TEXT NOT NULL
            );
INSERT INTO operation_hardware_targets VALUES('operation-4','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de','2026-08-22T00:00:10+00:00');
CREATE TABLE cutover_authorizations (
                id TEXT PRIMARY KEY,
                credential_sha256 TEXT NOT NULL UNIQUE,
                job_id TEXT NOT NULL,
                cassette_sequence INTEGER NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                catalog_binding_sha256 TEXT NOT NULL,
                assignment_sha256 TEXT NOT NULL,
                expected_label TEXT NOT NULL,
                host_id TEXT NOT NULL,
                drive_serial_sha256 TEXT NOT NULL,
                peer_kind TEXT NOT NULL CHECK(peer_kind = 'local_admin'),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by_operation_id TEXT REFERENCES daemon_operations(id)
            );
INSERT INTO cutover_authorizations VALUES('authorization-4','7777777777777777777777777777777777777777777777777777777777777777','JOB-MIGRATION',4,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','38854a15742514ddb8314e3e1ebbab5856aca79857f9c3703b45aae84c8566c8','2d1019fc924cc9b9debdb8c07707c2410d35c0b8c21d386565d62fdb309406ad','TAPE04','host-a','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','local_admin','2026-08-21T23:59:00+00:00','2026-08-22T01:00:00+00:00','2026-08-22T00:00:20+00:00','operation-4');
CREATE TABLE format_confirmations (
                operation_id TEXT PRIMARY KEY
                    REFERENCES daemon_operations(id) ON DELETE CASCADE,
                job_id TEXT NOT NULL,
                cassette_sequence INTEGER NOT NULL,
                expected_label TEXT NOT NULL,
                confirmed_by TEXT NOT NULL,
                confirmed_at TEXT NOT NULL
            );
CREATE TABLE hardware_command_executions (
                id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
                issued_generation INTEGER NOT NULL,
                command_kind TEXT NOT NULL,
                argv_sha256 TEXT NOT NULL,
                mount_path_sha256 TEXT NOT NULL CHECK(length(mount_path_sha256) = 64),
                tape_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(tape_device_identity_sha256) = 64),
                scsi_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(scsi_device_identity_sha256) = 64),
                expected_media_scope_sha256 TEXT NOT NULL
                    CHECK(length(expected_media_scope_sha256) = 64),
                observed_media_identity_sha256 TEXT CHECK(
                    observed_media_identity_sha256 IS NULL
                    OR length(observed_media_identity_sha256) = 64
                ),
                state TEXT NOT NULL CHECK(state IN (
                    'launch_reserved','launch_blocked','released','exit_observed','quiesced'
                )),
                boot_id TEXT,
                pid INTEGER,
                process_start_ticks INTEGER,
                process_group_id INTEGER,
                exit_outcome TEXT CHECK(exit_outcome IN (
                    'completed','terminated','launch_aborted'
                )),
                created_at TEXT NOT NULL,
                released_at TEXT,
                exit_observed_at TEXT,
                quiesced_at TEXT,
                CHECK (
                    (boot_id IS NULL AND pid IS NULL AND process_start_ticks IS NULL
                     AND process_group_id IS NULL)
                    OR
                    (boot_id IS NOT NULL AND pid IS NOT NULL
                     AND process_start_ticks IS NOT NULL AND process_group_id IS NOT NULL)
                )
            );
INSERT INTO hardware_command_executions VALUES('wait-4','operation-4',1,'wait_for_media','0000000000000000000000000000000000000000000000000000000000000258','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de',NULL,'quiesced','boot-wait-4',4201,5201,4201,'completed','2026-08-22T00:00:21+00:00','2026-08-22T00:00:22+00:00','2026-08-22T00:00:24+00:00','2026-08-22T00:00:24+00:00');
INSERT INTO hardware_command_executions VALUES('identify-4','operation-4',1,'identify','0000000000000000000000000000000000000000000000000000000000000259','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de',NULL,'quiesced','boot-identify-4',4202,5202,4202,'completed','2026-08-22T00:00:30+00:00','2026-08-22T00:00:31+00:00','2026-08-22T00:00:33+00:00','2026-08-22T00:00:33+00:00');
INSERT INTO hardware_command_executions VALUES('unmount-4','operation-4',1,'unmount','000000000000000000000000000000000000000000000000000000000000025a','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de','8888888888888888888888888888888888888888888888888888888888888888','quiesced','boot-unmount-4',4203,5203,4203,'completed','2026-08-22T00:02:00+00:00','2026-08-22T00:02:10+00:00','2026-08-22T00:02:30+00:00','2026-08-22T00:02:30+00:00');
INSERT INTO hardware_command_executions VALUES('status-4','operation-4',1,'status','5555555555555555555555555555555555555555555555555555555555555555','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de','8888888888888888888888888888888888888888888888888888888888888888','quiesced','boot-status-4',4204,5204,4204,'completed','2026-08-22T06:20:35.400020+00:00','2026-08-22T06:20:35.400248+00:00','2026-08-22T06:20:35.400248+00:00','2026-08-22T06:20:35.400248+00:00');
INSERT INTO hardware_command_executions VALUES('unload-4','operation-4',1,'unload','4444444444444444444444444444444444444444444444444444444444444444','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de','8888888888888888888888888888888888888888888888888888888888888888','quiesced','boot-unload-4',4100,5100,4100,'terminated','2026-08-22T06:20:35.401362+00:00','2026-08-22T06:20:35.401606+00:00','2026-08-22T06:20:35.401607+00:00','2026-08-22T06:20:35.401607+00:00');
CREATE TABLE operation_media_identity_bindings (
                operation_id TEXT PRIMARY KEY
                    REFERENCES operation_hardware_targets(operation_id),
                observed_media_identity_sha256 TEXT NOT NULL
                    CHECK(length(observed_media_identity_sha256) = 64),
                bound_by_command_id TEXT NOT NULL REFERENCES hardware_command_executions(id),
                bound_at TEXT NOT NULL
            );
INSERT INTO operation_media_identity_bindings VALUES('operation-4','8888888888888888888888888888888888888888888888888888888888888888','identify-4','2026-08-22T00:00:34+00:00');
CREATE TABLE command_quiescence_receipts (
                id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
                reconciled_by_generation INTEGER NOT NULL,
                recorded_at TEXT NOT NULL
            );
CREATE TABLE command_quiescence_receipt_items (
                receipt_id TEXT NOT NULL
                    REFERENCES command_quiescence_receipts(id) ON DELETE CASCADE,
                command_id TEXT NOT NULL REFERENCES hardware_command_executions(id),
                exit_outcome TEXT NOT NULL CHECK(exit_outcome IN (
                    'completed','terminated','launch_aborted'
                )),
                PRIMARY KEY(receipt_id, command_id)
            );
CREATE TABLE physical_reconciliation_receipts (
                id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
                reconciled_by_generation INTEGER NOT NULL,
                command_receipt_id TEXT NOT NULL REFERENCES command_quiescence_receipts(id),
                mount_path_sha256 TEXT CHECK(
                    mount_path_sha256 IS NULL OR length(mount_path_sha256) = 64
                ),
                tape_device_identity_sha256 TEXT CHECK(
                    tape_device_identity_sha256 IS NULL
                    OR length(tape_device_identity_sha256) = 64
                ),
                scsi_device_identity_sha256 TEXT CHECK(
                    scsi_device_identity_sha256 IS NULL
                    OR length(scsi_device_identity_sha256) = 64
                ),
                expected_media_scope_sha256 TEXT CHECK(
                    expected_media_scope_sha256 IS NULL
                    OR length(expected_media_scope_sha256) = 64
                ),
                observed_media_identity_sha256 TEXT CHECK(
                    observed_media_identity_sha256 IS NULL
                    OR length(observed_media_identity_sha256) = 64
                ),
                mounted INTEGER NOT NULL CHECK(mounted = 0),
                media_loaded INTEGER NOT NULL CHECK(media_loaded = 0),
                drive_busy INTEGER NOT NULL CHECK(drive_busy = 0),
                related_process_count INTEGER NOT NULL CHECK(related_process_count = 0),
                recorded_at TEXT NOT NULL,
                CHECK (
                    (mount_path_sha256 IS NULL AND tape_device_identity_sha256 IS NULL
                     AND scsi_device_identity_sha256 IS NULL
                     AND expected_media_scope_sha256 IS NULL
                     AND observed_media_identity_sha256 IS NULL)
                    OR
                    (mount_path_sha256 IS NOT NULL
                     AND tape_device_identity_sha256 IS NOT NULL
                     AND scsi_device_identity_sha256 IS NOT NULL
                     AND expected_media_scope_sha256 IS NOT NULL)
                )
            );
CREATE TABLE phase_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
                owner_generation INTEGER NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN (
                    'identifying_media','formatting_media','mounting','writing',
                    'writing_manifest','finalizing_index','unmounting','committing','unloading'
                )),
                started_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL CHECK(duration_seconds >= 0),
                recorded_at TEXT NOT NULL
            );
CREATE TABLE audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                principal TEXT NOT NULL,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                request_id TEXT NOT NULL,
                remote_address TEXT,
                payload_json TEXT NOT NULL
            );
CREATE TABLE migration_receipts (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES automatic_jobs(id),
                bundle_sha256 TEXT NOT NULL CHECK(length(bundle_sha256) = 64),
                assignment_sha256 TEXT NOT NULL CHECK(length(assignment_sha256) = 64),
                recorded_at TEXT NOT NULL, cassette_plan_sha256 TEXT CHECK(cassette_plan_sha256 IS NULL OR length(cassette_plan_sha256)=64), completed_evidence_sha256 TEXT CHECK(completed_evidence_sha256 IS NULL OR length(completed_evidence_sha256)=64),
                UNIQUE(job_id, bundle_sha256)
            );
INSERT INTO migration_receipts VALUES('migration-receipt-20c91d68353c4d85848ba958ac15a6d8','JOB-MIGRATION','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','2d1019fc924cc9b9debdb8c07707c2410d35c0b8c21d386565d62fdb309406ad','2026-08-22T06:20:35.391993+00:00','51ed3d8672027948be4fd150b6b2b7c7bbcc167f1c64a4a56afc181b373c9964','508ab0da9cf79007859d0d82eaab3bbd2530ae5ec85b600d77c3e99c09b1c0de');
CREATE TABLE imported_job_policies (
                job_id TEXT PRIMARY KEY REFERENCES automatic_jobs(id),
                policy_kind TEXT NOT NULL DEFAULT 'frozen-allocation'
                    CHECK(policy_kind = 'frozen-allocation'),
                assignment_sha256 TEXT NOT NULL CHECK(length(assignment_sha256) = 64),
                bundle_sha256 TEXT NOT NULL CHECK(length(bundle_sha256) = 64),
                authority_state TEXT NOT NULL CHECK(authority_state IN (
                    'pre_cutover','active_linux'
                )),
                windows_authority TEXT NOT NULL CHECK(windows_authority IN (
                    'resumable','historical_read_only'
                )),
                rollback_allowed INTEGER NOT NULL CHECK(rollback_allowed IN (0, 1)),
                frozen_at TEXT NOT NULL,
                activated_by_operation TEXT REFERENCES daemon_operations(id),
                activated_at TEXT
            , cassette_plan_sha256 TEXT CHECK(cassette_plan_sha256 IS NULL OR length(cassette_plan_sha256)=64), completed_evidence_sha256 TEXT CHECK(completed_evidence_sha256 IS NULL OR length(completed_evidence_sha256)=64));
INSERT INTO imported_job_policies VALUES('JOB-MIGRATION','frozen-allocation','2d1019fc924cc9b9debdb8c07707c2410d35c0b8c21d386565d62fdb309406ad','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','active_linux','historical_read_only',0,'2026-08-22T06:20:35.391929+00:00','operation-4','2026-08-22T06:20:35.399298+00:00','51ed3d8672027948be4fd150b6b2b7c7bbcc167f1c64a4a56afc181b373c9964','508ab0da9cf79007859d0d82eaab3bbd2530ae5ec85b600d77c3e99c09b1c0de');
CREATE TABLE daemon_ownership (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                owner_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                claimed_at TEXT NOT NULL
            );
INSERT INTO daemon_ownership VALUES(1,'daemon-b',2,'2026-08-22T06:20:35.402673+00:00');
CREATE TABLE daemon_event_sequence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reserved_at TEXT NOT NULL
            );
CREATE TABLE recovery_resolutions (
                operation_id TEXT PRIMARY KEY REFERENCES daemon_operations(id),
                resolved_by_generation INTEGER NOT NULL,
                reason_code TEXT NOT NULL,
                command_receipt_id TEXT NOT NULL REFERENCES command_quiescence_receipts(id),
                physical_receipt_id TEXT NOT NULL
                    REFERENCES physical_reconciliation_receipts(id),
                resolved_at TEXT NOT NULL
            );
CREATE TABLE imported_cassette_commit_receipts (
                job_id TEXT NOT NULL REFERENCES imported_job_policies(job_id),
                sequence INTEGER NOT NULL CHECK(sequence = 4),
                operation_id TEXT NOT NULL UNIQUE REFERENCES daemon_operations(id),
                owner_generation INTEGER NOT NULL CHECK(owner_generation > 0),
                migration_receipt_id TEXT NOT NULL REFERENCES migration_receipts(id),
                cutover_authorization_id TEXT NOT NULL
                    REFERENCES cutover_authorizations(id),
                cutover_authorization_sha256 TEXT NOT NULL
                    CHECK(length(cutover_authorization_sha256) = 64),
                evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
                manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
                tape_id TEXT NOT NULL REFERENCES tapes(id),
                block_ids_json TEXT NOT NULL,
                command_ids_json TEXT NOT NULL,
                command_evidence_sha256 TEXT NOT NULL
                    CHECK(length(command_evidence_sha256) = 64),
                commit_binding_sha256 TEXT NOT NULL
                    CHECK(length(commit_binding_sha256) = 64),
                observed_media_identity_sha256 TEXT NOT NULL
                    CHECK(length(observed_media_identity_sha256) = 64),
                mount_path_sha256 TEXT NOT NULL CHECK(length(mount_path_sha256) = 64),
                tape_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(tape_device_identity_sha256) = 64),
                scsi_device_identity_sha256 TEXT NOT NULL
                    CHECK(length(scsi_device_identity_sha256) = 64),
                expected_media_scope_sha256 TEXT NOT NULL
                    CHECK(length(expected_media_scope_sha256) = 64),
                committed_at TEXT NOT NULL,
                PRIMARY KEY(job_id, sequence)
            );
INSERT INTO imported_cassette_commit_receipts VALUES('JOB-MIGRATION',4,'operation-4',1,'migration-receipt-20c91d68353c4d85848ba958ac15a6d8','authorization-4','f1de5ec2f26c9df4a1bd6cd23d50cc6ec5a4fd39d6d29f37eaabe2bbf2d698de','0773aa300692be6be919335e7f52d177485674d45069ad04a362ce9697361da8','449f03006072c042678cb3a0961119bc1e8c6e01a61234ddc044692aae094bdb','TAPE04','["BLOCK04-01","BLOCK04-02"]','["wait-4","identify-4","unmount-4"]','289051daf0088d8138fe1be831fa4c4a39fcb33355a7e101626262b15dd50121','4db96d3b7e77fb498f342693357348de597498be41a8bd8e646cd0bfaa213642','8888888888888888888888888888888888888888888888888888888888888888','4836d9838fc08987e6e30ea8ae97978e1174595cb31034e611b81e92618e7c87','e68e8ddce967ad73d8d0b2221827e638dcdf5433cc34768a493ab5a6c7798b61','1d931aa33f58e8ccf9f6ef0d3637da4d26d1f69a3dca125fec3feac4ef72974f','66a19a5ff95dd0f098ab149b90e66042b14bd0140ddf48991922e0a73c59f3de','2026-08-22T06:20:35.399298+00:00');
CREATE TABLE imported_recovery_lineage_receipts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence = 4),
    operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
    original_owner_generation INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL,
    daemon_owner_id TEXT NOT NULL,
    prior_lineage_id TEXT REFERENCES imported_recovery_lineage_receipts(id),
    commit_binding_sha256 TEXT NOT NULL CHECK(length(commit_binding_sha256) = 64),
    restart_state TEXT NOT NULL CHECK(restart_state IN (
        'running','recovery_required'
    )),
    command_ids_json TEXT NOT NULL,
    command_evidence_sha256 TEXT NOT NULL
        CHECK(length(command_evidence_sha256) = 64),
    recorded_at TEXT NOT NULL,
    lineage_sha256 TEXT NOT NULL CHECK(length(lineage_sha256) = 64),
    UNIQUE(operation_id, recovery_generation)
);
INSERT INTO imported_recovery_lineage_receipts VALUES('recovery-lineage-0ea8a36b106f4b57a437f4222a7965c9','JOB-MIGRATION',4,'operation-4',1,2,'daemon-b',NULL,'4db96d3b7e77fb498f342693357348de597498be41a8bd8e646cd0bfaa213642','recovery_required','["status-4","unload-4"]','826afa05f5562249f95291a7c3e376cf4e10699f33246075e984e00028db7006','2026-08-22T06:20:35.402840+00:00','ded0214f9a20bfc134d4cee0d50fd7518d130a454421806460815e5dc75cc577');
CREATE TABLE imported_postcommit_command_receipts (
                command_id TEXT PRIMARY KEY REFERENCES hardware_command_executions(id),
                operation_id TEXT NOT NULL REFERENCES daemon_operations(id),
                job_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence = 4),
                issued_generation INTEGER NOT NULL,
                recovery_lineage_id TEXT
                    REFERENCES imported_recovery_lineage_receipts(id),
                command_order INTEGER NOT NULL CHECK(command_order > 0),
                command_evidence_sha256 TEXT NOT NULL
                    CHECK(length(command_evidence_sha256) = 64),
                recorded_at TEXT NOT NULL,
                UNIQUE(operation_id, command_order)
            );
INSERT INTO imported_postcommit_command_receipts VALUES('status-4','operation-4','JOB-MIGRATION',4,1,NULL,1,'bf1906345f77345887bead60ead6c51e6286f8408d982fdde0777caa3a147ef0','2026-08-22T06:20:35.400518+00:00');
INSERT INTO imported_postcommit_command_receipts VALUES('unload-4','operation-4','JOB-MIGRATION',4,1,NULL,2,'ddf4b93a6b6364e57d1929a1dd91918f6ed7b6ba6d293df4f8e357b8f48b4ea2','2026-08-22T06:20:35.402545+00:00');
CREATE TABLE imported_recovery_resolution_receipts (
                operation_id TEXT PRIMARY KEY REFERENCES daemon_operations(id),
                recovery_lineage_id TEXT
                    REFERENCES imported_recovery_lineage_receipts(id),
                commit_binding_sha256 TEXT NOT NULL
                    CHECK(length(commit_binding_sha256) = 64),
                resolved_generation INTEGER NOT NULL,
                command_receipt_id TEXT NOT NULL
                    REFERENCES command_quiescence_receipts(id),
                physical_receipt_id TEXT NOT NULL
                    REFERENCES physical_reconciliation_receipts(id),
                resolved_at TEXT NOT NULL,
                resolution_evidence_sha256 TEXT NOT NULL
                    CHECK(length(resolution_evidence_sha256) = 64)
            );
CREATE TABLE hardware_command_release_authorizations (
                command_id TEXT PRIMARY KEY
                    REFERENCES hardware_command_executions(id) ON DELETE CASCADE,
                permit_sha256 TEXT NOT NULL CHECK(length(permit_sha256) = 64),
                release_status TEXT NOT NULL CHECK(release_status IN (
                    'authorized','released','aborted','ambiguous'
                )),
                authorized_at TEXT NOT NULL,
                confirmed_at TEXT
            );
INSERT INTO hardware_command_release_authorizations VALUES('wait-4','00000000000000000000000000000000000000000000000000000000000002bd','released','2026-08-22T00:00:22+00:00','2026-08-22T00:00:22+00:00');
INSERT INTO hardware_command_release_authorizations VALUES('identify-4','00000000000000000000000000000000000000000000000000000000000002be','released','2026-08-22T00:00:31+00:00','2026-08-22T00:00:31+00:00');
INSERT INTO hardware_command_release_authorizations VALUES('unmount-4','00000000000000000000000000000000000000000000000000000000000002bf','released','2026-08-22T00:02:10+00:00','2026-08-22T00:02:10+00:00');
INSERT INTO hardware_command_release_authorizations VALUES('status-4','a9df296b9f349e743301aa053d08b3211c37f1b0fd553cca367b38db78291a27','released','2026-08-22T06:20:35.400197+00:00','2026-08-22T06:20:35.400248+00:00');
INSERT INTO hardware_command_release_authorizations VALUES('unload-4','5fdd74ade9047645cc289a8490eaeed9ba0594b81e118bd9bfc6e5f27e42fa6f','released','2026-08-22T06:20:35.401556+00:00','2026-08-22T06:20:35.401606+00:00');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('events',58);
INSERT INTO sqlite_sequence VALUES('file_versions',8);
CREATE TRIGGER freeze_imported_job_identity_update
            BEFORE UPDATE OF id, media_key, library_id, total_cassettes, force_format
            ON automatic_jobs
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.id
            ) AND (
                NEW.id IS NOT OLD.id
                OR NEW.media_key IS NOT OLD.media_key
                OR NEW.library_id IS NOT OLD.library_id
                OR NEW.total_cassettes IS NOT OLD.total_cassettes
                OR NEW.force_format IS NOT OLD.force_format
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_job_delete
            BEFORE DELETE ON automatic_jobs
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_insert
            BEFORE INSERT ON automatic_cassettes
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=NEW.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_identity_update
            BEFORE UPDATE OF job_id, sequence, physical_label, tape_serial,
                planned_files, planned_bytes, operation, reuse_registered
            ON automatic_cassettes
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id
            ) AND (
                NEW.job_id IS NOT OLD.job_id
                OR NEW.sequence IS NOT OLD.sequence
                OR NEW.physical_label IS NOT OLD.physical_label
                OR NEW.tape_serial IS NOT OLD.tape_serial
                OR NEW.planned_files IS NOT OLD.planned_files
                OR NEW.planned_bytes IS NOT OLD.planned_bytes
                OR NEW.operation IS NOT OLD.operation
                OR NEW.reuse_registered IS NOT OLD.reuse_registered
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_delete
            BEFORE DELETE ON automatic_cassettes
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_job_library_insert
            BEFORE INSERT ON automatic_job_libraries
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=NEW.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_job_library_update
            BEFORE UPDATE ON automatic_job_libraries
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id OR policy.job_id=NEW.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_job_library_delete
            BEFORE DELETE ON automatic_job_libraries
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_item_insert
            BEFORE INSERT ON automatic_cassette_items
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=NEW.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_item_update
            BEFORE UPDATE ON automatic_cassette_items
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id OR policy.job_id=NEW.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE TRIGGER freeze_imported_cassette_item_delete
            BEFORE DELETE ON automatic_cassette_items
            WHEN EXISTS (
                SELECT 1 FROM imported_job_policies policy
                WHERE policy.job_id=OLD.job_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'imported frozen job plan is immutable');
            END;
CREATE INDEX ix_file_versions_latest
    ON file_versions(library_id, relative_path, id DESC);
CREATE INDEX ix_file_versions_tape
    ON file_versions(tape_id, library_id, visible);
CREATE INDEX ix_blocks_library
    ON blocks(library_id, started_at DESC);
CREATE INDEX ix_file_versions_parent ON file_versions(library_id, parent_path, visible, id DESC);
CREATE INDEX ix_automatic_cassette_items_queue
                ON automatic_cassette_items(job_id, sequence, item_sequence);
CREATE UNIQUE INDEX ux_daemon_one_blocking
                ON daemon_operations((1))
                WHERE state IN ('running','recovery_required');
CREATE INDEX ix_hardware_command_nonquiescent
                ON hardware_command_executions(operation_id, state)
                WHERE state != 'quiesced';
CREATE UNIQUE INDEX hardware_command_release_authorizations_permit_unique
            ON hardware_command_release_authorizations(permit_sha256)
            ;
CREATE UNIQUE INDEX ux_tapes_cassette_number ON tapes(cassette_number COLLATE NOCASE);
CREATE UNIQUE INDEX ux_tapes_ltfs_volume_label ON tapes(volume_label COLLATE NOCASE) WHERE filesystem COLLATE NOCASE = 'LTFS' AND trim(volume_label)<>'';
COMMIT;
