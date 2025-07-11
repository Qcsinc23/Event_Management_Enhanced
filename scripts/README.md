# QCS Event Management Scripts

This directory contains utility scripts for managing the QCS Event Management Application.

## Available Scripts

### setup.py
**Purpose:** Automated application setup and initialization
**Usage:** `python scripts/setup.py`
**Features:**
- Python version validation
- Virtual environment creation
- Dependency installation
- Database verification
- Environment configuration

### backup.py
**Purpose:** Create backups of database and application files
**Usage:** 
```bash
python scripts/backup.py                    # Full backup
python scripts/backup.py --type database    # Database only
python scripts/backup.py --type app         # Application only
python scripts/backup.py --list             # List backups
python scripts/backup.py --cleanup 30       # Remove backups older than 30 days
```

### health_check.py
**Purpose:** Monitor application health and system status
**Usage:**
```bash
python scripts/health_check.py                  # Basic health check
python scripts/health_check.py --check-running  # Include running app check
python scripts/health_check.py --full           # All checks
python scripts/health_check.py --json           # JSON output
python scripts/health_check.py --save-report health.json  # Save report
```

### test.py
**Purpose:** Comprehensive application testing suite
**Usage:** `python scripts/test.py`
**Features:**
- Authentication testing
- Database integrity checks
- Security validation
- Performance testing
- 22 comprehensive tests

## Quick Start Guide

1. **Initial Setup:**
   ```bash
   python scripts/setup.py
   ```

2. **Health Check:**
   ```bash
   python scripts/health_check.py
   ```

3. **Run Application:**
   ```bash
   python run.py
   ```

4. **Create Backup:**
   ```bash
   python scripts/backup.py
   ```

5. **Run Tests:**
   ```bash
   python scripts/test.py
   ```

## Maintenance Schedule

### Daily
- Health check: `python scripts/health_check.py --check-running`

### Weekly
- Full backup: `python scripts/backup.py`
- Test suite: `python scripts/test.py`

### Monthly
- Clean old backups: `python scripts/backup.py --cleanup 30`
- Dependencies check: `python scripts/health_check.py --full`

## Script Dependencies

All scripts are designed to work with the main application dependencies. Some scripts have additional requirements:
- `health_check.py` with `--check-running`: requires `requests` library
- `backup.py`: uses only Python standard library
- `setup.py`: uses only Python standard library
- `test.py`: requires full application dependencies

## Error Handling

All scripts include comprehensive error handling and will provide helpful error messages and suggestions for resolution.

## Configuration

Scripts automatically detect and use:
- Virtual environment (if present)
- `.env` files for configuration
- Application directory structure

No additional configuration required for basic usage.
