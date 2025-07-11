# Calendar and Event API Routes Blueprint
import sqlite3
from flask import Blueprint, jsonify, request, abort, url_for, redirect, flash, make_response, session, render_template, Response
from datetime import datetime, timedelta
import ics  # Requires pip install ics
import requests
from io import StringIO
import uuid
import csv

# Sample ICS data for populating the database
ICS_EVENTS = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//QCS Event Management//ICS Export//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VEVENT
UID:20250715-devils-youth-hockey@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250715T190000
DTEND;TZID=America/New_York:20250715T220000
SUMMARY:NJ Devils (Youth Hockey Parents Night)
LOCATION:Newark
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250717-colon-health@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250717T111500
DTEND;TZID=America/New_York:20250717T141500
SUMMARY:Colon Health Month
LOCATION:Newport Mall
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250721-basketball-championship@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250721T120000
DTEND;TZID=America/New_York:20250721T150000
SUMMARY:NJ Basketball State Championship
LOCATION:Piscataway
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250722-basketball-championship-toms-river@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250722T120000
DTEND;TZID=America/New_York:20250722T150000
SUMMARY:NJ Basketball State Championship
LOCATION:Toms River
DESCRIPTION:Client: RWJ
STATUS:CANCELLED
END:VEVENT
BEGIN:VEVENT
UID:20250723-basketball-championship-toms-river2@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250723T120000
DTEND;TZID=America/New_York:20250723T150000
SUMMARY:NJ Basketball State Championship
LOCATION:Toms River
DESCRIPTION:Client: RWJ
STATUS:CANCELLED
END:VEVENT
BEGIN:VEVENT
UID:20250723-black-family-wellness@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250723T090000
DTEND;TZID=America/New_York:20250723T170000
SUMMARY:Black Family Wellness Expo
LOCATION:Jackson
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250728-emergency-care-conference@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250728T090000
DTEND;TZID=America/New_York:20250729T170000
SUMMARY:NJ Emergency Care Conference
LOCATION:Atlantic City
DESCRIPTION:Client: RWJ; Setup & Breakdown
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250729-devils-nurses-night@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250729T190000
DTEND;TZID=America/New_York:20250729T220000
SUMMARY:NJ Devils (Nurse's Night)
LOCATION:Newark
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250801-standing-in-solidarity@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250801T180000
DTEND;TZID=America/New_York:20250801T210000
SUMMARY:Standing in Solidarity
LOCATION:Newark
DESCRIPTION:Client: RWJ
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250801-devils-tenative@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250801T193000
DTEND;TZID=America/New_York:20250801T223000
SUMMARY:NJ Devils
LOCATION:Newark
DESCRIPTION:Client: RWJ
STATUS:TENTATIVE
END:VEVENT
BEGIN:VEVENT
UID:20250804-nj-nln@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250804T090000
DTEND;TZID=America/New_York:20250805T170000
SUMMARY:NJ NLN
LOCATION:Atlantic City
DESCRIPTION:Client: RWJ; Setup & Breakdown
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250808-womens-health@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250808T090000
DTEND;TZID=America/New_York:20250808T170000
SUMMARY:Let's Talk Women's Health
LOCATION:Newark
DESCRIPTION:Client: Horizon
STATUS:CONFIRMED
END:VEVENT
BEGIN:VEVENT
UID:20250809-movies-snow-white@qcseventmgmt.com
DTSTAMP:20250710T120000Z
DTSTART;TZID=America/New_York:20250809T143000
DTEND;TZID=America/New_York:20250809T173000
SUMMARY:Movies with Benefits (Snow White)
LOCATION:Secaucus
DESCRIPTION:Client: B2Y
STATUS:CONFIRMED
END:VEVENT
END:VCALENDAR"""

# Create the blueprint
calendar_bp = Blueprint('calendar', __name__, url_prefix='')

# Import needed functions from app.py
# This will be imported when the blueprint is registered in app.py
# Try to import WeasyPrint for PDF generation
try:
    from weasyprint import HTML
    weasyprint_available = True
except (ImportError, OSError):
    weasyprint_available = False
    print("WeasyPrint not available. PDF generation will be disabled.")

# Import helpers from the new helpers module
from helpers import get_db, login_required, role_required
import tempfile
from flask import send_file

# Calendar view route
@calendar_bp.route('/calendar')
@login_required
def calendar():
    """Display calendar view of events"""
    db = get_db()
    # Get all events for calendar display
    events = db.execute(
        'SELECT e.*, c.name as client_name, c.color as client_color '
        'FROM events e JOIN clients c ON e.client_id = c.id '
        'ORDER BY e.event_date'
    ).fetchall()
    
    # Get clients for the new event form
    clients = db.execute('SELECT * FROM clients').fetchall()
    
    # Get categories for the filter
    categories = db.execute('SELECT * FROM event_categories').fetchall()
    
    # Get locations for quick add
    locations = db.execute('SELECT * FROM locations WHERE is_active = 1').fetchall()
    
    return render_template('calendar.html', 
                           events=events, 
                           clients=clients,
                           categories=categories,
                           locations=locations)

# Export calendar as ICS
@calendar_bp.route('/export-calendar/<format>')
@login_required
def export_calendar(format):
    """Export calendar in various formats"""
    if format == 'ics':
        # Create a new calendar
        calendar = ics.Calendar()
        
        # Get all events
        db = get_db()
        events = db.execute(
            '''SELECT e.*, c.name as client_name, l.name as location_name, 
                      l.address as location_address
               FROM events e
               LEFT JOIN clients c ON e.client_id = c.id
               LEFT JOIN locations l ON e.location_id = l.id
               WHERE e.status != 'cancelled' '''
        ).fetchall()
        
        # Add each event to the calendar
        for event in events:
            # Use existing ics_uid or generate a new one
            cal_event = ics.Event(uid=event['ics_uid'] or str(uuid.uuid4()))
            cal_event.name = event['event_name']
            
            # Set event start
            start_str = f"{event['event_date']}T{event['drop_off_time'] or '09:00:00'}"
            cal_event.begin = datetime.strptime(start_str, '%Y-%m-%dT%H:%M:%S')
            
            # Set event end
            if event['end_date']:
                end_str = f"{event['end_date']}T{event['pickup_time'] or '17:00:00'}"
                cal_event.end = datetime.strptime(end_str, '%Y-%m-%dT%H:%M:%S')
            else:
                end_str = f"{event['event_date']}T{event['pickup_time'] or '17:00:00'}"
                cal_event.end = datetime.strptime(end_str, '%Y-%m-%dT%H:%M:%S')
            
            # Add description and location
            description_parts = []
            if event['client_name']:
                description_parts.append(f"Client: {event['client_name']}")
            if event['notes']:
                description_parts.append(event['notes'])
            
            cal_event.description = "\n".join(description_parts)
            
            # Set location
            location_parts = []
            if event['event_location']:
                location_parts.append(event['event_location'])
            elif event['location_name']:
                location_parts.append(event['location_name'])
                if event['location_address']:
                    location_parts.append(event['location_address'])
            
            if location_parts:
                cal_event.location = ", ".join(location_parts)
            
            # Add status
            if event['status'] == 'booked':
                cal_event.status = 'CONFIRMED'
            elif event['status'] == 'cancelled':
                cal_event.status = 'CANCELLED'
            else:
                cal_event.status = 'TENTATIVE'
            
            # Add URL
            cal_event.url = url_for('calendar.view_event', event_id=event['event_id'], _external=True)
            
            # Add to calendar
            calendar.events.add(cal_event)
        
        # Return as attachment
        response = make_response(str(calendar))
        response.headers['Content-Type'] = 'text/calendar'
        response.headers['Content-Disposition'] = 'attachment; filename=calendar.ics'
        return response
    
    # Other formats could be added here (JSON, XML, etc.)
    abort(400)

# Import calendar from ICS file or URL
@calendar_bp.route('/import-calendar', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def import_calendar():
    """Import calendar from ICS file or URL"""
    import_type = request.form.get('import_type', 'ics_file')
    category_id = request.form.get('category_id')
    
    try:
        calendar = None
        
        if import_type == 'ics_file':
            # Import from uploaded file
            if 'ics_file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(url_for('calendar_bp.calendar'))
            
            file = request.files['ics_file']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('calendar_bp.calendar'))
            
            # Parse ICS file
            ics_content = file.read().decode('utf-8')
            calendar = ics.Calendar(ics_content)

        elif import_type == 'csv_file':
            if 'csv_file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(url_for('calendar.calendar'))

            file = request.files['csv_file']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('calendar.calendar'))
            
            # Process CSV file
            try:
                # Read the CSV file in-memory
                stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_reader = csv.DictReader(stream)
                
                db = get_db()
                imported_count = 0
                
                # Get client and category maps
                clients = db.execute("SELECT id, name FROM clients").fetchall()
                client_map = {client['name'].lower(): client['id'] for client in clients}

                categories = db.execute("SELECT id, name FROM event_categories").fetchall()
                category_map = {cat['name'].lower(): cat['id'] for cat in categories}

                for row in csv_reader:
                    # Extract data from CSV row
                    event_name = row.get('event_name')
                    event_date = row.get('event_date')
                    client_name = row.get('client_name')

                    if not all([event_name, event_date, client_name]):
                        flash(f"Skipping row due to missing required fields: {row}", 'warning')
                        continue

                    # Find client_id with more flexible matching
                    client_id = None
                    csv_client_name_lower = client_name.lower()

                    for client in clients:
                        db_client_name_lower = client['name'].lower()
                        
                        # 1. Check for direct substring match (e.g., "Horizon" in "Horizon Blue Cross")
                        if csv_client_name_lower in db_client_name_lower:
                            client_id = client['id']
                            break

                        # 2. Check for acronym match (e.g., "RWJ" for "Robert Wood Johnson")
                        name_parts = db_client_name_lower.split()
                        if len(name_parts) > 1:
                            acronym = "".join(part[0] for part in name_parts)
                            if csv_client_name_lower == acronym:
                                client_id = client['id']
                                break
                    
                    if not client_id:
                        flash(f"Client '{client_name}' not found. Skipping event '{event_name}'.", 'warning')
                        continue

                    # --- DUPLICATE CHECK ---
                    existing_event = db.execute(
                        'SELECT event_id FROM events WHERE event_name = ? AND client_id = ? AND event_date = ?',
                        (event_name, client_id, event_date)
                    ).fetchone()

                    if existing_event:
                        flash(f"Skipped duplicate event: '{event_name}' on {event_date}", 'info')
                        continue
                    
                    # Find category_id if provided
                    category_name = row.get('category_name')
                    category_id = category_map.get(category_name.lower()) if category_name else None

                    # Insert into database
                    cursor = db.execute(
                        '''INSERT INTO events 
                           (event_name, client_id, category_id, event_date, drop_off_time, 
                            pickup_time, event_location, onsite_contact, manager, items_needed, 
                            boxes_from_pi, notes, status, ics_uid) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (
                            event_name,
                            client_id,
                            category_id,
                            event_date,
                            row.get('start_time'),
                            row.get('pickup_time'),
                            row.get('location_address'),
                            row.get('onsite_contact'),
                            row.get('manager'),
                            row.get('items_needed'),
                            row.get('boxes_from_pi'),
                            row.get('notes'),
                            'booked',
                            str(uuid.uuid4())
                        )
                    )
                    event_id = cursor.lastrowid
                    imported_count += 1

                    # --- EQUIPMENT ASSIGNMENT ---
                    items_needed_str = row.get('items_needed', '')
                    if items_needed_str:
                        # Get all available equipment from DB
                        all_equipment = db.execute('SELECT id, name FROM equipment').fetchall()
                        
                        # Split items from CSV, handling different separators
                        items_to_assign = [item.strip() for item in items_needed_str.replace(';',',').split(',') if item.strip()]

                        for item_string in items_to_assign:
                            # --- Enhanced Equipment Matching & Creation ---
                            matched_equipment = None
                            # First, try to find an exact match
                            for equipment in all_equipment:
                                if equipment['name'].lower() == item_string.lower():
                                    matched_equipment = equipment
                                    break
                            
                            # If no exact match, try partial match
                            if not matched_equipment:
                                for equipment in all_equipment:
                                    if equipment['name'].lower() in item_string.lower():
                                        matched_equipment = equipment
                                        break

                            # If still no match, create the equipment
                            if not matched_equipment:
                                # Create a new record only in the 'equipment' table
                                cursor = db.execute(
                                    "INSERT INTO equipment (name, description, quantity, status) VALUES (?, ?, ?, ?)",
                                    (item_string, 'Auto-created during CSV import', 1, 'available')
                                )
                                new_equipment_id = cursor.lastrowid
                                matched_equipment = {'id': new_equipment_id, 'name': item_string}
                                
                                # Add to our local list of all_equipment to avoid re-creating it in the same import session
                                all_equipment.append(matched_equipment)
                                flash(f"Created new equipment item: '{item_string}'", "info")

                            # Assign the matched or newly created equipment
                            if matched_equipment:
                                quantity = 1  # Assuming quantity of 1 for now
                                
                                # Check if this equipment is already assigned to this event to avoid duplicates
                                already_assigned = db.execute(
                                    'SELECT 1 FROM equipment_assignments WHERE event_id = ? AND equipment_id = ?',
                                    (event_id, matched_equipment['id'])
                                ).fetchone()

                                if not already_assigned:
                                    db.execute(
                                        '''INSERT INTO equipment_assignments (event_id, equipment_id, quantity, assigned_by)
                                           VALUES (?, ?, ?, ?)''',
                                        (event_id, matched_equipment['id'], quantity, session.get('user_id'))
                                    )
                
                db.commit()
                flash(f'Successfully imported {imported_count} events from CSV', 'success')
                return redirect(url_for('calendar.calendar'))

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')
                return redirect(url_for('calendar.calendar'))
            
        elif import_type == 'ics_url':
            # Import from URL
            ics_url = request.form.get('ics_url')
            if not ics_url:
                flash('URL is required', 'danger')
                return redirect(url_for('calendar_bp.calendar'))
            
            # Fetch ICS content from URL
            response = requests.get(ics_url)
            if response.status_code != 200:
                flash(f'Failed to fetch ICS: {response.status_code}', 'danger')
                return redirect(url_for('calendar_bp.calendar'))
            
            # Parse ICS content
            calendar = ics.Calendar(response.text)
            
            # If auto-sync is enabled, save the URL for later sync
            if request.form.get('auto_sync'):
                db = get_db()
                db.execute(
                    'INSERT INTO calendar_feeds (url, category_id, created_by) VALUES (?, ?, ?)',
                    (ics_url, category_id, session.get('user_id', None))
                )
                db.commit()
        
        if not calendar:
            flash('Invalid calendar data', 'danger')
            return redirect(url_for('calendar_bp.calendar'))
        
        # Get default client for imported events
        db = get_db()
        default_client = db.execute('SELECT id FROM clients LIMIT 1').fetchone()
        if not default_client:
            flash('No clients available to assign events to', 'danger')
            return redirect(url_for('calendar_bp.calendar'))
        
        # Process the calendar events
        imported_count = 0
        for event in calendar.events:
            # Extract event details
            event_name = event.name
            
            # Extract dates
            start_date = event.begin.date().strftime('%Y-%m-%d')
            start_time = event.begin.time().strftime('%H:%M:%S')
            
            if hasattr(event, 'end') and event.end:
                end_date = event.end.date().strftime('%Y-%m-%d')
                end_time = event.end.time().strftime('%H:%M:%S')
                
                # Check if this is a multi-day event
                if end_date != start_date:
                    is_multi_day = True
                else:
                    is_multi_day = False
                    end_date = None
            else:
                end_date = None
                end_time = None
                is_multi_day = False
            
            # Check if an event with this UID already exists
            event_uid = getattr(event, 'uid', None) or str(uuid.uuid4())
            existing_event = db.execute(
                'SELECT event_id FROM events WHERE ics_uid = ?', 
                (event_uid,)
            ).fetchone()
            
            if existing_event:
                # Update the existing event
                db.execute(
                    '''UPDATE events SET 
                       event_name = ?, client_id = ?, category_id = ?, 
                       event_date = ?, end_date = ?, drop_off_time = ?, 
                       pickup_time = ?, event_location = ?, status = ?, 
                       notes = ?, is_all_day = ?
                       WHERE ics_uid = ?''',
                    (
                        event_name,
                        default_client['id'], 
                        category_id,
                        start_date,
                        end_date,
                        start_time,
                        end_time,
                        getattr(event, 'location', '') or '',
                        'booked',  # Default status
                        getattr(event, 'description', '') or '',
                        0 if start_time and end_time else 1,  # All-day if no times
                        event_uid
                    )
                )
            else:
                # Create a new event
                db.execute(
                    '''INSERT INTO events 
                       (event_name, client_id, category_id, event_date, end_date,
                        drop_off_time, pickup_time, event_location, status, notes, is_all_day, ics_uid) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        event_name,
                        default_client['id'], 
                        category_id,
                        start_date,
                        end_date,
                        start_time,
                        end_time,
                        getattr(event, 'location', '') or '',
                        'booked',  # Default status
                        getattr(event, 'description', '') or '',
                        0 if start_time and end_time else 1,  # All-day if no times
                        event_uid
                    )
                )
            imported_count += 1
        
        db.commit()
        flash(f'Successfully imported {imported_count} events', 'success')
        return redirect(url_for('calendar_bp.calendar'))
        
    except Exception as e:
        flash(f'Error importing calendar: {str(e)}', 'danger')
        return redirect(url_for('calendar_bp.calendar'))

# API endpoint to get all events for the calendar
@calendar_bp.route('/api/events')
@login_required
def api_events():
    """API endpoint to get all events for the calendar, with filtering."""
    db = get_db()

    # Base query
    query = '''
        SELECT e.*, 
               c.name as client_name, 
               c.color as client_color,
               ec.name as category_name,
               ec.color as category_color,
               l.name as location_name
        FROM events e 
        LEFT JOIN clients c ON e.client_id = c.id
        LEFT JOIN event_categories ec ON e.category_id = ec.id
        LEFT JOIN locations l ON e.location_id = l.id
    '''
    
    # --- Dynamic WHERE clause construction ---
    conditions = []
    params = []

    # 1. Date Range Filtering (Required for calendar view)
    start = request.args.get('start')
    end = request.args.get('end')
    if start and end:
        # Improved logic: Include events that overlap with the requested date range
        # An event is visible if its start date is before the view's end date,
        # AND its end date (or event_date if no end_date) is after the view's start date
        conditions.append('''
            (e.event_date <= ? AND 
             COALESCE(e.end_date, e.event_date) >= ?)
        ''')
        params.extend([end, start])

    # 2. Category Filtering
    categories = request.args.get('categories')
    if categories:
        category_ids = [cat.strip() for cat in categories.split(',') if cat.strip()]
        if category_ids:
            placeholders = ','.join(['?'] * len(category_ids))
            # Include events with NULL category_id OR matching category_id
            conditions.append(f"(e.category_id IS NULL OR e.category_id IN ({placeholders}))")
            params.extend(category_ids)

    # 3. Status Filtering
    statuses = request.args.get('statuses')
    if statuses:
        status_list = [stat.strip() for stat in statuses.split(',') if stat.strip()]
        if status_list:
            placeholders = ','.join(['?'] * len(status_list))
            conditions.append(f"e.status IN ({placeholders})")
            params.extend(status_list)

    # 4. Client Filtering
    client_id = request.args.get('client_id')
    if client_id and client_id != 'all':
        conditions.append("e.client_id = ?")
        params.append(client_id)

    # 5. Conflicts Only Filtering
    conflicts_only = request.args.get('conflicts_only')
    if conflicts_only and conflicts_only.lower() == 'true':
        conditions.append("e.has_conflicts = 1")

    # --- Assemble the final query ---
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += ' ORDER BY e.event_date'
    
    events = db.execute(query, params).fetchall()
    
    # Convert to list of dicts for JSON serialization
    events_list = []
    for event in events:
        # Basic event details
        # Handle time formatting - add seconds if missing
        start_time = event['drop_off_time'] or '00:00:00'
        if start_time and len(start_time) == 5:  # Format is HH:MM
            start_time += ':00'
        
        event_dict = {
            'id': event['event_id'],
            'title': event['event_name'],
            'start': f"{event['event_date']}T{start_time}",
            'color': event['category_color'] or event['client_color'] or '#3788d8',
            'textColor': '#ffffff',
            'borderColor': event['client_color'] or '#3788d8',
            'url': url_for('calendar.view_event', event_id=event['event_id']),
            'allDay': bool(event['is_all_day'])
        }
        
        # Add end date if it exists
        if event['end_date']:
            # For all-day events, FullCalendar needs exclusive end date
            if event['is_all_day']:
                # Parse end_date and add 1 day
                end_date = datetime.strptime(event['end_date'], '%Y-%m-%d')
                end_date = end_date + timedelta(days=1)
                event_dict['end'] = end_date.strftime('%Y-%m-%d')
            else:
                event_dict['end'] = f"{event['end_date']}T{event['pickup_time'] or '23:59:59'}"
        elif event['pickup_time']:
            # Single-day event with end time
            end_time = event['pickup_time']
            if end_time and len(end_time) == 5:  # Format is HH:MM
                end_time += ':00'
            event_dict['end'] = f"{event['event_date']}T{end_time}"
        
        # Add classes for styling
        classNames = []
        if event['status']:
            classNames.append(f"event-{event['status']}")
        if event['has_conflicts']:
            classNames.append('event-conflict')
        if event['is_recurring']:
            classNames.append('event-recurring')
        
        if classNames:
            event_dict['classNames'] = classNames
        
        # Add extended properties
        event_dict['extendedProps'] = {
            'client_id': event['client_id'],
            'client_name': event['client_name'],
            'category_id': event['category_id'],
            'category_name': event['category_name'],
            'location': event['event_location'] or event['location_name'],
            'location_id': event['location_id'],
            'status': event['status'],
            'is_recurring': bool(event['is_recurring']),
            'has_conflicts': bool(event['has_conflicts']),
            'parent_event_id': event['parent_event_id']
        }
        
        events_list.append(event_dict)
    
    return jsonify(events_list)

# API endpoint to quickly add an event from the calendar
@calendar_bp.route('/api/events/quick_add', methods=['POST'])
@login_required
def api_quick_add_event():
    """API endpoint to quickly add an event from the calendar"""
    try:
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        client_id = request.form.get('client_id')
        category_id = request.form.get('category_id')
        location_id = request.form.get('location_id')
        
        error = None
        if not event_name:
            error = 'Event name is required'
        elif not event_date:
            error = 'Date is required'
        elif not client_id:
            error = 'Client is required'
        
        if error:
            return jsonify({'success': False, 'message': error}), 400
        
        db = get_db()
        cursor = db.execute(
            '''INSERT INTO events 
               (event_name, client_id, category_id, event_date, location_id, status, ics_uid)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (event_name, client_id, category_id, event_date, location_id, 'booked', str(uuid.uuid4()))
        )
        db.commit()
        
        event_id = cursor.lastrowid
        
        # Get the newly created event
        event = db.execute(
            '''SELECT e.*, 
                   c.name as client_name, 
                   c.color as client_color,
                   ec.name as category_name,
                   ec.color as category_color
               FROM events e 
               LEFT JOIN clients c ON e.client_id = c.id
               LEFT JOIN event_categories ec ON e.category_id = ec.id
               WHERE e.event_id = ?''',
            (event_id,)
        ).fetchone()
        
        # Convert to dict for response
        event_data = {
            'id': event['event_id'],
            'title': event['event_name'],
            'start': event['event_date'],
            'color': event['category_color'] or event['client_color'] or '#3788d8',
            'allDay': True,
            'extendedProps': {
                'client_id': event['client_id'],
                'client_name': event['client_name'],
                'status': event['status']
            }
        }
        
        return jsonify({
            'success': True, 
            'message': 'Event created successfully',
            'event': event_data
        })
        
    except sqlite3.Error as db_err:
        print(f"Database error in api_quick_add_event: {db_err}")
        return jsonify({'success': False, 'message': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Exception in api_quick_add_event: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# API endpoint to update event dates/times when moved on calendar
@calendar_bp.route('/api/events/update_dates', methods=['POST'])
@login_required
def api_update_event_dates():
    """API endpoint to update event dates/times when moved on calendar"""
    try:
        event_id = request.form['event_id']
        start_date = request.form['start_date']
        end_date = request.form.get('end_date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        recurrence_edit = request.form.get('recurrence_edit', 'single')
        
        db = get_db()
        
        # Get the event to check if it's recurring
        event = db.execute('SELECT * FROM events WHERE event_id = ?', (event_id,)).fetchone()
        
        if not event:
            return jsonify({'success': False, 'message': 'Event not found'}), 404
        
        # Update logic depends on whether this is a recurring event
        if event['is_recurring'] and recurrence_edit != 'single':
            if recurrence_edit == 'all':
                # Update all instances
                events_to_update = db.execute(
                    'SELECT event_id FROM events WHERE event_id = ? OR parent_event_id = ?',
                    (event_id, event_id)
                ).fetchall()
                
                for e in events_to_update:
                    db.execute(
                        '''UPDATE events SET 
                           event_date = ?, end_date = ?, drop_off_time = ?, pickup_time = ?
                           WHERE event_id = ?''',
                        (start_date, end_date, start_time, end_time, e['event_id'])
                    )
            elif recurrence_edit == 'future':
                # Get the original date of the current event
                original_date = event['event_date']
                
                # Update this event and all future events in the series
                events_to_update = db.execute(
                    '''SELECT event_id FROM events 
                       WHERE (event_id = ? OR parent_event_id = ?) 
                       AND event_date >= ?''',
                    (event_id, event_id, original_date)
                ).fetchall()
                
                for e in events_to_update:
                    db.execute(
                        '''UPDATE events SET 
                           event_date = ?, end_date = ?, drop_off_time = ?, pickup_time = ?
                           WHERE event_id = ?''',
                        (start_date, end_date, start_time, end_time, e['event_id'])
                    )
        else:
            # Just update this single event
            db.execute(
                '''UPDATE events SET 
                   event_date = ?, end_date = ?, drop_off_time = ?, pickup_time = ?
                   WHERE event_id = ?''',
                (start_date, end_date, start_time, end_time, event_id)
            )
        
        # Now check for conflicts
        conflicts = check_event_conflicts(db, event_id, start_date, end_date)
        if conflicts:
            # Mark event as having conflicts
            db.execute('UPDATE events SET has_conflicts = 1 WHERE event_id = ?', (event_id,))
            
            # Record the specific conflicts
            for conflict in conflicts:
                db.execute(
                    '''INSERT INTO event_conflicts 
                       (event_id, conflicting_event_id, conflict_type)
                       VALUES (?, ?, ?)''',
                    (event_id, conflict['conflict_event_id'], conflict['conflict_type'])
                )
        
        db.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Event dates updated successfully',
            'has_conflicts': bool(conflicts),
            'conflicts': conflicts
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# API endpoint to check for equipment/location conflicts
@calendar_bp.route('/api/events/check_conflicts', methods=['POST'])
@login_required
def api_check_event_conflicts():
    """API endpoint to check for equipment/location conflicts"""
    try:
        event_id = request.form['event_id']
        start_date = request.form['start_date']
        end_date = request.form.get('end_date')
        
        db = get_db()
        conflicts = check_event_conflicts(db, event_id, start_date, end_date)
        
        return jsonify({
            'success': True,
            'conflicts': conflicts
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Helper function to check for event conflicts
def check_event_conflicts(db, event_id, start_date, end_date=None):
    """Check for equipment/location conflicts for an event"""
    if not end_date:
        end_date = start_date
        
    # Find events that overlap with the given date range
    overlapping_events = db.execute(
        '''SELECT event_id FROM events 
           WHERE event_id != ? AND 
                 (
                     (event_date BETWEEN ? AND ?) OR
                     (end_date BETWEEN ? AND ?) OR
                     (event_date <= ? AND (end_date IS NULL OR end_date >= ?))
                 ) AND
                 status != 'cancelled' ''',
        (event_id, start_date, end_date, start_date, end_date, start_date, start_date)
    ).fetchall()
    
    conflicts = []
    
    # Check for equipment conflicts
    # Get equipment assigned to this event
    event_equipment = db.execute(
        'SELECT equipment_id FROM equipment_assignments WHERE event_id = ?',
        (event_id,)
    ).fetchall()
    
    for equipment in event_equipment:
        equipment_id = equipment['equipment_id']
        
        # Check if any overlapping events use this equipment
        for other_event in overlapping_events:
            other_id = other_event['event_id']
            
            conflict = db.execute(
                'SELECT 1 FROM equipment_assignments WHERE event_id = ? AND equipment_id = ?',
                (other_id, equipment_id)
            ).fetchone()
            
            if conflict:
                conflicts.append({
                    'conflict_event_id': other_id,
                    'conflict_type': 'equipment',
                    'equipment_id': equipment_id
                })
    
    # Check for location conflicts
    event = db.execute('SELECT location_id FROM events WHERE event_id = ?', (event_id,)).fetchone()
    
    if event and event['location_id']:
        location_id = event['location_id']
        
        # Check if any overlapping events use this location
        for other_event in overlapping_events:
            other_id = other_event['event_id']
            
            conflict = db.execute(
                'SELECT 1 FROM events WHERE event_id = ? AND location_id = ?',
                (other_id, location_id)
            ).fetchone()
            
            if conflict:
                conflicts.append({
                    'conflict_event_id': other_id,
                    'conflict_type': 'location',
                    'location_id': location_id
                })
    
    return conflicts

# Event routes
@calendar_bp.route('/events/new', methods=['GET', 'POST'])
@login_required
def new_event():
    """Create a new event"""
    db = get_db()
    
    if request.method == 'POST':
        title = request.form['event_name']
        client_id = request.form['client_id']
        event_date = request.form['event_date']
        drop_off_time = request.form['drop_off_time']
        pick_up_time = request.form['pickup_time']
        # Get location from either location_id or event_location
        location_id = request.form.get('location_id')
        event_location = request.form.get('event_location', '')
        
        # Use event_location if provided, otherwise use empty string
        location = event_location
        status = request.form.get('status', 'booked')
        notes = request.form.get('notes', '')
        template_id = request.form.get('template_id') or None
        
        # Get category_id - either directly provided or from template
        category_id = request.form.get('category_id') or None
        
        # Get equipment selections from form
        equipment_ids = request.form.getlist('equipment_ids')
        equipment_qtys = {}
        for eq_id in equipment_ids:
            qty_key = f'equipment_qty{eq_id}'
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0:
                        equipment_qtys[eq_id] = qty
                except ValueError:
                    pass
        
        # If a template is selected, apply template data
        if template_id:
            # Get template details
            template = db.execute('SELECT * FROM event_templates WHERE id = ?', 
                                 (template_id,)).fetchone()
            
            # Use template category if no category is explicitly selected
            if not category_id and template['category_id']:
                category_id = template['category_id']
                
            # Get template equipment if needed
            if not equipment_qtys and request.form.get('use_template_equipment') == 'yes':
                template_equipment = db.execute(
                    'SELECT equipment_id, quantity FROM template_equipment WHERE template_id = ?',
                    (template_id,)
                ).fetchall()
                
                for te in template_equipment:
                    equipment_qtys[str(te['equipment_id'])] = te['quantity']
        
        error = None
        if not title:
            error = 'Title is required'
        elif not client_id:
            error = 'Client is required'
        elif not event_date:
            error = 'Event date is required'
        
        if error is not None:
            flash(error, 'danger')
        else:
            # Create the event with template reference if used
            cursor = db.execute(
                '''INSERT INTO events 
                   (event_name, client_id, category_id, event_date, drop_off_time, 
                    pickup_time, event_location, status, notes, template_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (title, client_id, category_id, event_date, drop_off_time, 
                 pick_up_time, location, status, notes, template_id)
            )
            event_id = cursor.lastrowid
            
            # Add equipment assignments
            for eq_id, qty in equipment_qtys.items():
                # Verify there's enough available equipment
                available = db.execute(
                    '''SELECT (e.quantity - COALESCE(
                           (SELECT SUM(ea.quantity) FROM equipment_assignments ea 
                            WHERE ea.equipment_id = e.id), 0)
                       ) as available
                       FROM equipment e WHERE e.id = ?''',
                    (eq_id,)
                ).fetchone()['available']
                
                if available >= qty:
                    db.execute(
                        '''INSERT INTO equipment_assignments 
                           (event_id, equipment_id, quantity) 
                           VALUES (?, ?, ?)''',
                        (event_id, eq_id, qty)
                    )
                else:
                    flash(f'Warning: Could only assign {available} units of equipment #{eq_id}', 'warning')
                    if available > 0:
                        db.execute(
                            '''INSERT INTO equipment_assignments 
                               (event_id, equipment_id, quantity) 
                               VALUES (?, ?, ?)''',
                            (event_id, eq_id, available)
                        )
            
            db.commit()
            flash('Event created successfully', 'success')
            return redirect(url_for('calendar.calendar'))
    
    # Get clients, categories, templates and equipment for the form
    clients = db.execute('SELECT * FROM clients ORDER BY name').fetchall()
    categories = db.execute('SELECT * FROM event_categories ORDER BY name').fetchall()
    templates = db.execute(
        '''SELECT t.*, c.name as category_name 
           FROM event_templates t 
           LEFT JOIN event_categories c ON t.category_id = c.id
           ORDER BY t.name'''
    ).fetchall()
    equipment_list = db.execute(
        '''SELECT e.*, 
           (e.quantity - COALESCE(
               (SELECT SUM(ea.quantity) FROM equipment_assignments ea 
                WHERE ea.equipment_id = e.id), 0)
           ) as assigned
           FROM equipment e 
           ORDER BY e.name'''
    ).fetchall()
    
    # Pre-select client if passed in query param
    selected_client = request.args.get('client_id')
    
    return render_template(
        'new_event.html', 
        clients=clients,
        categories=categories,
        templates=templates,
        equipment=equipment_list,
        selected_client=selected_client
    )

@calendar_bp.route('/events/<int:event_id>')
@login_required
def view_event(event_id):
    """View event details"""
    db = get_db()
    event = db.execute(
        'SELECT e.*, c.name as client_name, c.color as client_color '
        'FROM events e JOIN clients c ON e.client_id = c.id '
        'WHERE e.event_id = ?',
        (event_id,)
    ).fetchone()
    
    if event is None:
        abort(404)
    
    # Check if an invoice exists for this event
    invoice = db.execute('SELECT * FROM invoices WHERE event_id = ?', (event_id,)).fetchone()
    
    # Get equipment assignments for this event
    equipment_assignments = db.execute(
        '''SELECT ea.quantity, e.name, e.description 
           FROM equipment_assignments ea
           JOIN equipment e ON ea.equipment_id = e.id
           WHERE ea.event_id = ?''',
        (event_id,)
    ).fetchall()
    
    return render_template('view_event.html', event=event, invoice=invoice, 
                          equipment_assignments=equipment_assignments)

@calendar_bp.route('/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    """Edit an existing event"""
    db = get_db()
    event = db.execute('SELECT * FROM events WHERE event_id = ?', (event_id,)).fetchone()
    
    if event is None:
        abort(404)
    
    if request.method == 'POST':
        event_name = request.form['title']  # Form still uses 'title'
        client_id = request.form['client_id']
        event_date = request.form['event_date']
        drop_off_time = request.form['drop_off_time']
        pickup_time = request.form['pick_up_time']  # Form uses 'pick_up_time', but DB uses 'pickup_time'
        event_location = request.form['location']  # Form uses 'location', but DB uses 'event_location'
        status = request.form['status']
        
        # Get equipment selections from form
        equipment_ids = request.form.getlist('equipment_ids')
        equipment_qtys = {}
        for eq_id in equipment_ids:
            qty_key = f'equipment_qty{eq_id}'
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0:
                        equipment_qtys[eq_id] = qty
                except ValueError:
                    pass
        
        error = None
        if not event_name:
            error = 'Event name is required'
        elif not client_id:
            error = 'Client is required'
        elif not event_date:
            error = 'Event date is required'
        
        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                'UPDATE events SET event_name = ?, client_id = ?, event_date = ?, drop_off_time = ?, '
                'pickup_time = ?, event_location = ?, status = ? WHERE event_id = ?',
                (event_name, client_id, event_date, drop_off_time, pickup_time, event_location, status, event_id)
            )
            
            # Update equipment assignments
            # First, remove existing assignments
            db.execute('DELETE FROM equipment_assignments WHERE event_id = ?', (event_id,))
            
            # Add new equipment assignments
            for eq_id, qty in equipment_qtys.items():
                # Verify there's enough available equipment
                available = db.execute(
                    '''SELECT (e.quantity - COALESCE(
                           (SELECT SUM(ea.quantity) FROM equipment_assignments ea 
                            WHERE ea.equipment_id = e.id AND ea.event_id != ?), 0)
                       ) as available
                       FROM equipment e WHERE e.id = ?''',
                    (event_id, eq_id)
                ).fetchone()['available']
                
                if available >= qty:
                    db.execute(
                        '''INSERT INTO equipment_assignments 
                           (event_id, equipment_id, quantity) 
                           VALUES (?, ?, ?)''',
                        (event_id, eq_id, qty)
                    )
                else:
                    flash(f'Warning: Could only assign {available} units of equipment #{eq_id}', 'warning')
                    if available > 0:
                        db.execute(
                            '''INSERT INTO equipment_assignments 
                               (event_id, equipment_id, quantity) 
                               VALUES (?, ?, ?)''',
                            (event_id, eq_id, available)
                        )
            
            db.commit()
            
            # If status is changed to completed, generate an invoice
            if status == 'completed' and event['status'] != 'completed':
                # Calculate amount based on some business rules
                # For example, $100 per hour between drop-off and pick-up
                amount = 100.00  # Simplified for this example
                
                db.execute(
                    'INSERT INTO invoices (event_id, client_id, amount, issue_date, status) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (event_id, client_id, amount, datetime.now().strftime('%Y-%m-%d'), 'unpaid')
                )
                db.commit()
                flash('Invoice generated for this event', 'info')
            
            flash('Event updated successfully', 'success')
            return redirect(url_for('calendar.view_event', event_id=event_id))
    
    # Get clients for the dropdown
    clients = db.execute('SELECT * FROM clients').fetchall()
    
    # Get equipment with availability info
    equipment = db.execute(
        '''SELECT e.*,
           (e.quantity - COALESCE(
               (SELECT SUM(ea.quantity) FROM equipment_assignments ea 
                WHERE ea.equipment_id = e.id AND ea.event_id != ?), 0)
           ) as available_qty
           FROM equipment e 
           ORDER BY e.name''',
        (event_id,)
    ).fetchall()
    
    # Get current equipment assignments for this event
    current_assignments = db.execute(
        'SELECT equipment_id, quantity FROM equipment_assignments WHERE event_id = ?',
        (event_id,)
    ).fetchall()
    
    # Convert equipment to list of dicts and add assignment info
    equipment_list = []
    for item in equipment:
        equipment_item = dict(item)
        equipment_item['assigned_to_event'] = False
        equipment_item['assigned_qty'] = 0
        
        # Check if this equipment is assigned to the event
        for assignment in current_assignments:
            if assignment['equipment_id'] == item['id']:
                equipment_item['assigned_to_event'] = True
                equipment_item['assigned_qty'] = assignment['quantity']
                break
        
        equipment_list.append(equipment_item)
    
    return render_template('edit_event.html', event=event, clients=clients, equipment=equipment_list)

@calendar_bp.route('/events/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    """Delete an event"""
    db = get_db()
    db.execute('DELETE FROM events WHERE event_id = ?', (event_id,))
    db.commit()
    flash('Event deleted successfully', 'success')
    return redirect(url_for('calendar.calendar'))

@calendar_bp.route('/events/<int:event_id>/complete', methods=['POST'])
@login_required
def complete_event(event_id):
    """Mark an event as completed and generate an invoice"""
    db = get_db()
    event = db.execute('SELECT * FROM events WHERE event_id = ?', (event_id,)).fetchone()
    
    if event is None:
        abort(404)
    
    # Check if event is already completed
    if event['status'] == 'completed':
        flash('Event is already marked as completed', 'info')
        return redirect(url_for('calendar.view_event', event_id=event_id))
    
    # Check if event can be completed (must be booked or in_progress)
    if event['status'] not in ['booked', 'confirmed', 'in_progress']:
        flash('Event cannot be completed from its current status', 'danger')
        return redirect(url_for('calendar.view_event', event_id=event_id))
    
    try:
        # Update event status to completed
        db.execute(
            'UPDATE events SET status = ?, last_updated = ?, last_updated_by = ? WHERE event_id = ?',
            ('completed', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session.get('user_id'), event_id)
        )
        
        # Check if an invoice already exists for this event
        existing_invoice = db.execute('SELECT id FROM invoices WHERE event_id = ?', (event_id,)).fetchone()
        
        if not existing_invoice:
            # Calculate amount based on some business rules
            # For now, using a simple calculation - $150 base rate
            # In a real application, this could be based on:
            # - Duration of event
            # - Equipment used
            # - Client-specific rates
            # - etc.
            
            # Get equipment assignments to calculate a more accurate amount
            equipment_assignments = db.execute(
                '''SELECT ea.quantity, e.name
                   FROM equipment_assignments ea
                   JOIN equipment e ON ea.equipment_id = e.id
                   WHERE ea.event_id = ?''',
                (event_id,)
            ).fetchall()
            
            # Base rate + equipment charges
            base_amount = 150.00
            equipment_amount = len(equipment_assignments) * 25.00  # $25 per equipment item
            total_amount = base_amount + equipment_amount
            
            # Generate invoice
            db.execute(
                'INSERT INTO invoices (event_id, client_id, amount, issue_date, due_date, status, created_by) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (
                    event_id,
                    event['client_id'],
                    total_amount,
                    datetime.now().strftime('%Y-%m-%d'),
                    (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),  # 30 days payment terms
                    'unpaid',
                    session.get('user_id')
                )
            )
            
            db.commit()
            flash(f'Event marked as completed and invoice generated for ${total_amount:.2f}', 'success')
        else:
            db.commit()
            flash('Event marked as completed', 'success')
        
        # Return JSON response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({
                'success': True,
                'message': 'Event marked as completed and invoice generated',
                'invoice_generated': not existing_invoice
            })
        
        return redirect(url_for('calendar.view_event', event_id=event_id))
        
    except Exception as e:
        db.rollback()
        flash(f'Error completing event: {str(e)}', 'danger')
        
        # Return JSON response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({
                'success': False,
                'message': f'Error completing event: {str(e)}'
            })
        
        return redirect(url_for('calendar.view_event', event_id=event_id))

# Invoice routes
@calendar_bp.route('/invoices')
@login_required
def invoices():
    """List all invoices"""
    db = get_db()
    invoices = db.execute(
        'SELECT i.*, e.event_name as event_title, c.name as client_name, c.color as client_color '
        'FROM invoices i '
        'JOIN events e ON i.event_id = e.event_id '
        'JOIN clients c ON i.client_id = c.id '
        'ORDER BY i.issue_date DESC'
    ).fetchall()
    
    return render_template('invoices.html', invoices=invoices)

@calendar_bp.route('/invoices/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    """View invoice details"""
    db = get_db()
    invoice = db.execute(
        'SELECT i.*, e.event_name as event_title, e.event_date, e.drop_off_time, e.pickup_time, '
        'e.event_location, c.name as client_name, c.color as client_color '
        'FROM invoices i '
        'JOIN events e ON i.event_id = e.event_id '
        'JOIN clients c ON i.client_id = c.id '
        'WHERE i.id = ?',
        (invoice_id,)
    ).fetchone()
    
    if invoice is None:
        abort(404)
    
    return render_template('view_invoice.html', invoice=invoice)

@calendar_bp.route('/invoices/<int:invoice_id>/pdf')
@login_required
def generate_invoice_pdf(invoice_id):
    """Generate a PDF invoice"""
    # Check if WeasyPrint is available
    if not weasyprint_available:
        flash('PDF generation is not available due to missing dependencies. Please install WeasyPrint and its requirements.', 'warning')
        return redirect(url_for('calendar.view_invoice', invoice_id=invoice_id))
    
    db = get_db()
    invoice = db.execute(
        'SELECT i.*, e.event_name as event_title, e.event_date, e.drop_off_time, e.pickup_time, '
        'e.event_location, e.status as event_status, c.name as client_name, c.color as client_color, '
        'c.address as client_address, c.city as client_city, c.state as client_state, '
        'c.zip as client_zip, c.contact_person as client_contact '
        'FROM invoices i '
        'JOIN events e ON i.event_id = e.event_id '
        'JOIN clients c ON i.client_id = c.id '
        'WHERE i.id = ?',
        (invoice_id,)
    ).fetchone()
    
    if invoice is None:
        abort(404)
    
    # Get equipment assignments for this event
    equipment_items = db.execute(
        '''SELECT ea.quantity, e.name, e.description 
           FROM equipment_assignments ea
           JOIN equipment e ON ea.equipment_id = e.id
           WHERE ea.event_id = ?''',
        (invoice['event_id'],)
    ).fetchall()
    
    # Render the invoice template
    html = render_template('invoice_pdf.html', 
                          invoice=invoice, 
                          equipment_items=equipment_items,
                          generated_date=datetime.now().strftime('%Y-%m-%d'))
    
    try:
        # Create a temporary file
        fd, path = tempfile.mkstemp(suffix='.pdf')
        
        # Generate PDF
        HTML(string=html).write_pdf(path)
        
        # Send the file
        return send_file(path, as_attachment=True, 
                        download_name=f"invoice_{invoice_id}.pdf",
                        mimetype='application/pdf')
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('calendar.view_invoice', invoice_id=invoice_id))

@calendar_bp.route('/invoices/<int:invoice_id>/mark_paid', methods=['POST'])
@login_required
def mark_invoice_paid(invoice_id):
    """Mark an invoice as paid"""
    db = get_db()
    db.execute('UPDATE invoices SET status = ? WHERE id = ?', ('paid', invoice_id))
    db.commit()
    flash('Invoice marked as paid', 'success')
    return redirect(url_for('calendar.view_invoice', invoice_id=invoice_id))

# Sample data import function

# Debug route for CSV import testing
@calendar_bp.route('/debug/csv-import-status')
@login_required
@role_required('admin')
def debug_csv_import():
    """Debug endpoint to check recent CSV imports"""
    db = get_db()
    
    # Get recent events (last 24 hours)
    recent_events = db.execute("""
        SELECT event_id, event_name, event_date, client_id, 
               (SELECT name FROM clients WHERE id = events.client_id) as client_name,
               datetime(date('now'), 'localtime') as current_time
        FROM events 
        WHERE date(event_date) >= date('now', '-1 day')
        ORDER BY event_id DESC 
        LIMIT 10
    """).fetchall()
    
    debug_info = {
        'recent_events': [dict(event) for event in recent_events],
        'total_events': db.execute("SELECT COUNT(*) as count FROM events").fetchone()['count'],
        'total_clients': db.execute("SELECT COUNT(*) as count FROM clients").fetchone()['count'],
        'clients': [dict(client) for client in db.execute("SELECT id, name FROM clients").fetchall()]
    }
    
    return jsonify(debug_info)


def import_sample_events():
    """Import sample events from the ICS_EVENTS data"""
    print("Starting sample ICS event import...")
    
    # Get database connection
    db = get_db()
    
    # Query clients table to create a mapping of names to IDs
    clients = db.execute("SELECT id, name FROM clients").fetchall()
    
    # Create client name to ID mapping
    client_map = {}
    for client in clients:
        # Store both exact match and lowercase version for case-insensitive lookup
        client_map[client['name']] = client['id']
        client_map[client['name'].lower()] = client['id']
        
        # Also add common abbreviations/aliases
        if 'robert wood johnson' in client['name'].lower() or 'rwj' in client['name'].lower():
            client_map['RWJ'] = client['id']
            client_map['rwj'] = client['id']
            client_map['Robert Wood Johnson'] = client['id']
        
        if 'horizon' in client['name'].lower():
            client_map['Horizon'] = client['id']
            client_map['horizon'] = client['id']
            
    print(f"Found {len(clients)} clients in the database")
    
    # Map ICS status to database status
    status_map = {
        'CONFIRMED': 'confirmed',
        'TENTATIVE': 'booked',
        'CANCELLED': 'cancelled'
    }
    
    # Parse the ICS string using ics library
    calendar = ics.Calendar(ICS_EVENTS)
    events = list(calendar.events)
    
    print(f"Found {len(events)} events in the ICS data")
    
    # Initialize counters
    inserted_count = 0
    updated_count = 0
    
    # Insert or update events in the database
    for ics_event in events:
        # Extract event details
        summary = ics_event.name
        uid = ics_event.uid
        
        print(f"Processing event: {summary} (UID: {uid})")
        
        # Extract dates and times
        start_date = ics_event.begin.date().strftime('%Y-%m-%d')
        start_time = ics_event.begin.time().strftime('%H:%M:%S')
        
        # Determine if all day event (no time component or duration is 24 hours)
        is_all_day = False
        if ics_event.all_day:
            is_all_day = True
            start_time = None
        
        # Handle end date/time
        end_date = None
        end_time = None
        if ics_event.end:
            end_date = ics_event.end.date().strftime('%Y-%m-%d')
            end_time = ics_event.end.time().strftime('%H:%M:%S')
            
            # Check if this is a multi-day event
            if end_date != start_date:
                # For multi-day events in FullCalendar:
                # - Regular events: Use the actual end date and time
                # - All-day events: End date is exclusive, so subtract 1 day for storage
                if is_all_day:
                    # Convert to datetime, subtract a day, convert back to string
                    end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
                    end_date_obj = end_date_obj - timedelta(days=1)
                    end_date = end_date_obj.strftime('%Y-%m-%d')
            else:
                # Same day event - no need for end_date
                end_date = None
        
        location = str(ics_event.location) if ics_event.location else ''
        description = str(ics_event.description) if ics_event.description else ''
        
        # Extract client information from description
        client_id = None  # Default to None
        if 'Client:' in description:
            # Extract client name from description
            client_part = description.split('Client:')[1].strip()
            client_name = client_part.split(';')[0].strip() if ';' in client_part else client_part
            
            # Look up client ID by name (case-insensitive)
            client_id = client_map.get(client_name) or client_map.get(client_name.lower())
            
            if not client_id:
                print(f"Client not found for name: {client_name}")
                # Use the first client as a fallback
                if clients:
                    client_id = clients[0]['id']
                    print(f"Using first client (ID: {client_id}) as fallback")
        
        # Determine status from ICS event status
        ics_status = getattr(ics_event, 'status', None)
        status = status_map.get(str(ics_status), 'booked') if ics_status else 'booked'
        
        # Check if event with this UID already exists using the ics_uid field
        existing_event = db.execute("SELECT event_id FROM events WHERE ics_uid = ?", (uid,)).fetchone()
        
        if existing_event:
            # Update existing event
            print(f"Updating existing event ID: {existing_event['event_id']}")
            try:
                db.execute("""
                    UPDATE events SET 
                      event_name = ?, 
                      event_date = ?, 
                      end_date = ?,
                      drop_off_time = ?, 
                      pickup_time = ?,
                      event_location = ?, 
                      notes = ?, 
                      status = ?,
                      client_id = ?,
                      is_all_day = ?
                    WHERE ics_uid = ?
                """, (
                    summary, 
                    start_date, 
                    end_date,
                    start_time, 
                    end_time,
                    location, 
                    description, 
                    status,
                    client_id,
                    1 if is_all_day else 0,
                    uid
                ))
                updated_count += 1
                print(f"Updated existing event: {summary}")
            except Exception as e:
                print(f"Error updating event: {e}")
        else:
            # Insert new event
            db.execute("""
                INSERT INTO events (
                  event_name, 
                  event_date, 
                  end_date,
                  drop_off_time, 
                  pickup_time,
                  event_location, 
                  notes, 
                  status,
                  client_id,
                  is_all_day,
                  ics_uid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                summary, 
                start_date, 
                end_date,
                start_time, 
                end_time,
                location, 
                description, 
                status,
                client_id,
                1 if is_all_day else 0,
                uid
            ))
            inserted_count += 1
            print(f"Inserted new event: {summary}")
    
    # Commit changes
    db.commit()
    
    print(f"Import complete: {inserted_count} events inserted, {updated_count} events updated.")
    return inserted_count + updated_count

# Route for importing sample events
@calendar_bp.route('/populate-sample-events', methods=['GET'])
@login_required
@role_required('admin')
def populate_sample_events():
    """Populate the database with sample events from ICS"""
    try:
        count = import_sample_events()
        flash(f"Successfully imported {count} sample events to the database", "success")
        return redirect(url_for('calendar.calendar'))
    except Exception as e:
        flash(f"Error importing sample events: {str(e)}", "danger")
        return redirect(url_for('calendar.calendar'))
