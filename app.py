from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key

BACKEND_URL = 'http://localhost:5001'  # Make sure this matches your backend port

# Define these at the top of your file
JOB_COST_TYPES = [
    'standard',
    'time_and_material',
    'conveyer_rental',
    'conveyer_rental_labor',
    'conveyer_rental_multiple',
    'landscape',
    'dumptruck_rental',
    'other'
]

WORK_TYPES = [
    'basement',
    'garage',
    'slab_on',
    'under_footing',
    'plumber_spray',
    'footings',
    'crawl_space',
    'heavy_blanket',
    'dry_blanket',
    'exterior_gravel',
    'track_out',
    'other'
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            response = requests.post(f'{BACKEND_URL}/login', json={
                'username': username,
                'password': password
            })
            
            if response.status_code == 200:
                data = response.json()
                session['user'] = {
                    'id': data['user']['id'],
                    'username': data['user']['username'],
                    'email': data['user']['email']
                }
                return redirect(url_for('dashboard'))
            else:
                error_message = response.json().get('error', 'Invalid username or password')
                return render_template('login.html', error=error_message)
                
        except requests.exceptions.ConnectionError:
            return render_template('login.html', error="Could not connect to the server")
        except Exception as e:
            print(f"Login error: {str(e)}")
            return render_template('login.html', error="An unexpected error occurred")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            
            print(f"Sending signup request with data: {{'username': '{username}', 'email': '{email}', 'password': '*****'}}")
            
            response = requests.post(f'{BACKEND_URL}/signup', json={
                'username': username,
                'email': email,
                'password': password
            })
            
            print(f"Backend response status: {response.status_code}")
            print(f"Backend response: {response.text}")
            
            if response.status_code == 201:
                return jsonify({'success': True})
            else:
                error_message = response.json().get('error', 'An error occurred. Please try again.')
                print(f"Error message: {error_message}")
                return jsonify({'error': error_message}), response.status_code
                
        except requests.exceptions.ConnectionError:
            print("Connection error to backend server")
            return jsonify({'error': "Could not connect to the server. Please try again."}), 500
        except Exception as e:
            print(f"Error during signup: {str(e)}")
            return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        return render_template('dashboard.html', 
                             username=session['user']['username'],
                             email=session['user']['email'])
    except KeyError:
        session.clear()
        return redirect(url_for('login'))

@app.route('/create-project/<region>', methods=['GET', 'POST'])
def create_project(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Work type mapping with properly formatted names
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

        # Job cost type mapping with properly formatted names
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
        display_work_types = [work_type_mapping.get(wt, wt.replace('_', ' ').title()) for wt in work_types]
        display_job_cost_types = [job_cost_mapping.get(jct, jct.replace('_', ' ').title()) for jct in job_cost_types]

        # Handle "other" options
        if 'other' in work_types:
            other_value = request.form.get('work_type_other')
            if other_value:
                display_work_types.remove('Other')
                display_work_types.append(f"Other: {other_value}")

        if 'other' in job_cost_types:
            other_value = request.form.get('job_cost_type_other')
            if other_value:
                display_job_cost_types.remove('Other')
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
                # Get the created project with ID from the response
                created_project = response.json().get('project')
                return render_template('confirmation.html', project=created_project)
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

@app.route('/day-view/<region>/<date>')
def day_view(region, date):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Fetch projects for this region and date from backend
    response = requests.get(f'{BACKEND_URL}/projects/{region}')
    if response.status_code == 200:
        all_projects = response.json()
        # Filter projects for this date
        projects = [p for p in all_projects if p['date'] == date]
    else:
        projects = []
    
    return render_template('day_view.html', 
                         region=region, 
                         date=date, 
                         projects=projects)

@app.route('/edit-project/<region>/<project_id>', methods=['GET', 'POST'])
def edit_project(region, project_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        # Get project data from backend
        response = requests.get(f'{BACKEND_URL}/projects/{region}/{project_id}')
        if response.status_code != 200:
            print(f"Error fetching project: {response.text}")
            return "Project not found", 404

        project = response.json()

        # Work type mapping with properly formatted names
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

        # Job cost type mapping with properly formatted names
        job_cost_mapping = {
            'standard': 'Standard',
            'time_and_material': 'Time and Material',
            'conveyer_rental': 'Conveyer Truck Rental',
            'conveyer_rental_labor': 'Conveyer Truck Rental and Labor',
            'conveyer_rental_multiple': 'Conveyer Truck Rental and Multiple Laborers',
            'landscape': 'Landscape',
            'dumptruck_rental': 'Dumptruck Rental'
        }

        if request.method == 'POST':
            # Get form data
            work_types = request.form.getlist('work_type')
            job_cost_types = request.form.getlist('job_cost_type')

            # Convert internal names to display names
            display_work_types = [work_type_mapping.get(wt, wt.replace('_', ' ').title()) for wt in work_types]
            display_job_cost_types = [job_cost_mapping.get(jct, jct.replace('_', ' ').title()) for jct in job_cost_types]

            # Update project data
            updated_project = {
                'id': project_id,
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

            # Send updated data to backend
            response = requests.put(
                f'{BACKEND_URL}/projects/{region}/{project_id}',
                json=updated_project
            )

            if response.status_code == 200:
                return render_template('edit_confirmation.html',
                                    project=updated_project,
                                    region=region)
            else:
                return "Error updating project", 500

        # For GET request, show edit form with formatted options
        formatted_work_types = [{'value': k, 'label': v} for k, v in work_type_mapping.items()]
        formatted_job_cost_types = [{'value': k, 'label': v} for k, v in job_cost_mapping.items()]
        
        return render_template('edit_project.html',
                             project=project,
                             region=region,
                             work_types=formatted_work_types,
                             job_cost_types=formatted_job_cost_types)
    except Exception as e:
        print(f"Exception in edit_project: {str(e)}")
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)