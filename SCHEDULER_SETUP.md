# Auto-Absent Marking Scheduler Setup

## Overview
The system now includes an auto-absent marking feature that creates Attendance records with status='Absent' for users who didn't check in on a specific date.

## How It Works

### Manual Trigger (Testing)
You can manually trigger the absent marking using the admin endpoint:

```bash
# Mark absent for yesterday (default)
curl -X POST http://localhost:5000/admin/mark-absent \
  -H "Content-Type: application/json" \
  -b cookies.txt

# Mark absent for specific date
curl -X POST http://localhost:5000/admin/mark-absent \
  -H "Content-Type: application/json" \
  -d '{"date": "2026-01-02"}' \
  -b cookies.txt
```

### Python Script Trigger
Create a script `mark_absent_daily.py`:

```python
import requests
from datetime import date, timedelta

# Login and get session
session = requests.Session()
login_response = session.post('http://localhost:5000/login', data={
    'username': 'admin',
    'password': 'your_admin_password'
})

# Mark absent for yesterday
yesterday = (date.today() - timedelta(days=1)).isoformat()
response = session.post(
    'http://localhost:5000/admin/mark-absent',
    json={'date': yesterday}
)

print(response.json())
```

## Automated Scheduling Options

### Option 1: Windows Task Scheduler
1. Save the Python script above as `mark_absent_daily.py`
2. Open Task Scheduler (taskschd.msc)
3. Create Basic Task:
   - Name: "Mark Daily Absent"
   - Trigger: Daily at 12:01 AM
   - Action: Start a program
   - Program: `python`
   - Arguments: `C:\path\to\mark_absent_daily.py`
   - Start in: `C:\path\to\project`

### Option 2: APScheduler (Python)
Install: `pip install APScheduler`

Add to `app.py`:
```python
from apscheduler.schedulers.background import BackgroundScheduler

def scheduled_absent_marking():
    with app.app_context():
        yesterday = date.today() - timedelta(days=1)
        mark_absent_for_date(yesterday)
        print(f"Auto-marked absent for {yesterday}")

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=scheduled_absent_marking,
    trigger="cron",
    hour=0,
    minute=1
)
scheduler.start()
```

### Option 3: Celery (Production)
Install: `pip install celery redis`

Create `celery_app.py`:
```python
from celery import Celery
from celery.schedules import crontab
from app import app, mark_absent_for_date
from datetime import date, timedelta

celery = Celery('tasks', broker='redis://localhost:6379/0')

@celery.task
def mark_yesterday_absent():
    with app.app_context():
        yesterday = date.today() - timedelta(days=1)
        result = mark_absent_for_date(yesterday)
        return result

celery.conf.beat_schedule = {
    'mark-absent-daily': {
        'task': 'celery_app.mark_yesterday_absent',
        'schedule': crontab(hour=0, minute=1)
    }
}
```

Run:
```bash
celery -A celery_app worker --loglevel=info
celery -A celery_app beat --loglevel=info
```

### Option 4: Linux Cron (if deploying on Linux)
Add to crontab (`crontab -e`):
```bash
1 0 * * * cd /path/to/project && python mark_absent_daily.py >> /var/log/absent_marking.log 2>&1
```

## Business Logic

### When to Run
- **Recommended**: Daily at 12:01 AM (after midnight)
- This marks the previous day's absent users
- Never run for the current day (still in progress)

### What It Does
1. Queries all users in the system
2. For each user, checks if they have an attendance record for the target date
3. If no record exists, creates one with:
   - `status = 'Absent'`
   - `check_in = None`
   - `check_out = None`
   - `duration_minutes = 0`
4. Returns count of marked absent vs already present

### Edge Cases
- Users on approved leave: Will need leave management integration (future feature)
- Weekends/holidays: Current implementation marks absent; add holiday calendar later
- New users: Will be marked absent for dates before their join date (filter by `user.created_at` if needed)

## Testing

1. Create a test user
2. Don't check in for a specific date
3. Run the admin endpoint for that date
4. Verify the attendance record is created with status='Absent'
5. Check the weekly overview shows the absence

## Security Notes

- Currently, any logged-in user can trigger the endpoint
- For production, add role-based access control
- Recommend restricting to admin users only:

```python
@app.route('/admin/mark-absent', methods=['POST'])
def admin_mark_absent():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':  # Add role field to User model
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    
    # ... rest of function
```

## Integration with Leave Management (Future)

When implementing leave management:
```python
def mark_absent_for_date(target_date: date):
    all_users = User.query.all()
    marked_count = 0
    
    for user in all_users:
        # Check if user has approved leave
        has_leave = Leave.query.filter_by(
            user_id=user.id,
            date=target_date,
            status='Approved'
        ).first()
        
        if has_leave:
            continue  # Skip users on approved leave
        
        existing_record = Attendance.query.filter_by(
            user_id=user.id,
            date=target_date
        ).first()
        
        if not existing_record:
            # Create absent record
            # ...
```

## Troubleshooting

**Issue**: Script runs but no records created
- Check database connection
- Verify users exist in system
- Check date format (YYYY-MM-DD)

**Issue**: "Unauthorized" error
- Ensure user is logged in before calling endpoint
- Check session cookie is included in request

**Issue**: Scheduler not running
- APScheduler: Check app stays running
- Celery: Ensure Redis is running and worker/beat are started
- Cron: Check cron service is enabled and script has execute permissions
