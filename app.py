from flask import Flask, render_template, request, redirect, url_for, session
import requests
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key

BACKEND_URL = 'http://localhost:5001'  # Make sure this matches your backend port

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        response = requests.post(f'{BACKEND_URL}/login', json={
            'username': username,
            'password': password
        })
        
        if response.status_code == 200:
            session['user'] = response.json()
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')
        
        response = requests.post(f'{BACKEND_URL}/signup', json={
            'username': username,
            'password': password
        })
        
        if response.status_code == 200:
            return redirect(url_for('login'))
        else:
            return render_template('signup.html', error='Username already exists')
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user']['username'])

@app.route('/create-project/<region>', methods=['GET', 'POST'])
def create_project(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Work type mapping
        work_type_mapping = {
            'basement': 'Basement',
            'garage': 'Garage',
            'slab_on': 'Slab On',
            'under_footing': 'Under Footing Fill',
            'plumber_spray': 'Plumber Spray',
            'footings': 'Footings',
            'crawl_space': 'Crawl Space',
            'heavy_blanket': 'Heavy Blanket Removal/Replace $250',
            'dry_blanket': 'Dry Blanket Removal',
            'exterior_gravel': 'Exterior Gravel Dump',
            'track_out': 'Track Out Pad'
        }

        # Job cost type mapping
        job_cost_mapping = {
            'standard': 'Standard',
            'time_and_material': 'Time and Material',
            'conveyer_rental': 'Conveyer Truck Rental',
            'conveyer_rental_labor': 'Conveyer Truck Rental and Labor',
            'conveyer_rental_multiple': 'Conveyer Truck Rental and Multiple Laborers',
            'landscape': 'Landscape',
            'dumptruck_rental': 'Dumptruck Rental'
        }

        # Get the form data
        work_types = request.form.getlist('work_type')
        job_cost_types = request.form.getlist('job_cost_type')

        # Convert internal names to display names
        display_work_types = [work_type_mapping.get(wt, wt) for wt in work_types]
        display_job_cost_types = [job_cost_mapping.get(jct, jct) for jct in job_cost_types]

        # Handle "other" options
        if 'other' in work_types:
            other_value = request.form.get('work_type_other')
            if other_value:
                display_work_types.remove(work_type_mapping.get('other', 'other'))
                display_work_types.append(f"Other: {other_value}")

        if 'other' in job_cost_types:
            other_value = request.form.get('job_cost_type_other')
            if other_value:
                display_job_cost_types.remove(job_cost_mapping.get('other', 'other'))
                display_job_cost_types.append(f"Other: {other_value}")

        project = {
            'date': request.form.get('date'),
            'po': request.form.get('po'),
            'customer_name': request.form.get('customer_name'),
            'customer_phone': request.form.get('customer_phone'),
            'customer_email': request.form.get('customer_email'),
            'address': request.form.get('address'),
            'city': request.form.get('city'),
            'subdivision': request.form.get('subdivision'),
            'lot_number': request.form.get('lot_number'),
            'square_footage': request.form.get('square_footage'),
            'job_cost_type': display_job_cost_types,
            'work_type': display_work_types,
            'notes': request.form.get('notes'),
            'region': region
        }

        try:
            response = requests.post(
                f'{BACKEND_URL}/projects/{region}',
                json=project,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                print(f"Project successfully saved for {region}")
                return render_template('confirmation.html', project=project)
            else:
                print(f"Error saving project: {response.text}")
                return "Error saving project", 500
        except Exception as e:
            print(f"Exception while saving project: {str(e)}")
            return "Error saving project", 500
    
    return render_template('create_project.html', region=region)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/calendar/<region>')
def calendar(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        # Fetch projects from backend
        response = requests.get(f'{BACKEND_URL}/projects/{region}')
        if response.status_code == 200:
            projects = response.json()
            print(f"Retrieved projects for {region}: {projects}")  # Debug print
        else:
            projects = []
            print(f"Error fetching projects: {response.text}")  # Debug print
    except Exception as e:
        projects = []
        print(f"Exception while fetching projects: {str(e)}")  # Debug print
    
    return render_template('calendar.html', region=region)

if __name__ == '__main__':
    app.run(port=5000, debug=True)