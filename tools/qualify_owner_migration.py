#!/usr/bin/env python3
"""Qualify a consistent DB copy and backup restoration; never migrates the input DB."""
import argparse, hashlib, json, os, sqlite3, subprocess
from pathlib import Path

def consistent_copy(source_path,destination_path):
    source=sqlite3.connect('file:'+str(source_path.resolve())+'?mode=ro',uri=True)
    destination=sqlite3.connect(destination_path)
    try:source.backup(destination)
    finally:destination.close();source.close()

def snapshot(path):
    with sqlite3.connect('file:'+str(path.resolve())+'?mode=ro',uri=True) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
        version=db.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]
        result={}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('schema_migrations','sqlite_sequence') ORDER BY name"):
            quoted='"'+name.replace('"','""')+'"'
            # Values remain private in memory; only aggregate digests are retained locally.
            rows=[]
            for row in db.execute('SELECT * FROM '+quoted):
                rows.append(json.dumps([{'blob':v.hex()} if isinstance(v,bytes) else v for v in row],sort_keys=True,separators=(',',':')))
            digest=hashlib.sha256('\n'.join(sorted(rows)).encode()).hexdigest()
            result[name]={'count':len(rows),'digest':digest}
        return version,result

def main():
    p=argparse.ArgumentParser();p.add_argument('--database',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--qualifier',type=Path,required=True);p.add_argument('--expected-before',type=int);p.add_argument('--expected-after',type=int);args=p.parse_args()
    os.umask(0o077);assert args.database.is_file();assert not args.output.exists()
    args.output.mkdir(mode=0o700,parents=True)
    backup=args.output/'consistent-backup.db';candidate=args.output/'migration-candidate.db';restored=args.output/'restored-backup.db'
    consistent_copy(args.database,backup)
    before,original=snapshot(backup)
    if args.expected_before is not None:assert before==args.expected_before,'unexpected input schema'
    consistent_copy(backup,candidate)
    completed=subprocess.run([str(args.qualifier.resolve()),str(candidate.resolve())],capture_output=True)
    if completed.returncode:raise RuntimeError('offline candidate migration failed; output intentionally suppressed')
    after,migrated=snapshot(candidate)
    assert after>=before
    if args.expected_after is not None:assert after==args.expected_after,'unexpected migrated schema'
    for table,values in original.items():assert migrated.get(table)==values,'owner table changed: '+table
    consistent_copy(backup,restored);restored_version,restored_rows=snapshot(restored)
    assert (restored_version,restored_rows)==(before,original)
    report={'schema_before':before,'schema_after':after,'preserved_tables':sorted(original),'restored_schema':restored_version,'migration_and_restore':'passed','production_database_migrated':False,'qualifier_sha256':hashlib.sha256(args.qualifier.read_bytes()).hexdigest()}
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
