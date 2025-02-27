# Changelog

All notable changes to the VIP Pizza Shop will be documented in this file.

## [0.1.0] - 2025-02-28

### Added
- Initial release
- Basic user authentication system
- Pizza ordering functionality
- Admin interface
- User registration
- Basic cart functionality
- README.md with student instructions
- Requirements.txt with dependencies
- Security report template

### Known Issues
- Some features may be intentionally vulnerable for educational purposes
- Database may need to be recreated if schema changes

## How to Update

1. Check your current version:
```bash
python check_version.py
```

2. Update your local copy:
```bash
git pull origin main
```

3. Install any new dependencies:
```bash
pip install -r requirements.txt
```

4. Reset the database (if needed):
```bash
python reset_db.py
```

## Version Verification
Each release includes a VERSION.md file with a unique hash. You can verify you have the correct version by comparing the hash in your VERSION.md with the official hash.
