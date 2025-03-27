from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key

BACKEND_URL = 'http://localhost:5001'  # Remove /api prefix since we're using specific prefixes for each route

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
            print(f"Attempting login for user: {username}")
            print(f"Request form data: {request.form}")
            
            # Send as form data instead of JSON
            response = requests.post(
                f'{BACKEND_URL}/auth/login',  # Updated to use /auth prefix
                data={
                    'username': username,
                    'password': password
                }
            )
            
            print(f"Login response status: {response.status_code}")
            print(f"Login response content: {response.text}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"Login successful. User data: {data}")
                    # Store complete user data in session
                    session['user'] = data['user']
                    print(f"Session data after login: {session['user']}")
                    return redirect(url_for('dashboard'))
                except Exception as e:
                    print(f"Error parsing response JSON: {str(e)}")
                    return render_template('login.html', error="Error processing server response")
            else:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', 'Invalid username or password')
                except:
                    error_message = 'Invalid username or password'
                print(f"Login failed: {error_message}")
                return render_template('login.html', error=error_message)
                
        except requests.exceptions.ConnectionError:
            print("Connection error to backend server")
            return render_template('login.html', error="Could not connect to the server")
        except Exception as e:
            print(f"Login error: {str(e)}")
            return render_template('login.html', error="An unexpected error occurred")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form

            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            
            print(f"Sending signup request with data: {{'username': '{username}', 'email': '{email}'}}")
            
            response = requests.post(f'{BACKEND_URL}/auth/signup', json={
                'username': username,
                'email': email,
                'password': password
            })
            
            print(f"Backend response status: {response.status_code}")
            
            if response.status_code == 201:
                if request.is_json:
                    return jsonify({'success': True})
                return redirect(url_for('login'))
            else:
                error_message = response.json().get('error', 'An error occurred during signup')
                if request.is_json:
                    return jsonify({'error': error_message}), response.status_code
                return render_template('signup.html', error=error_message)
                
        except requests.exceptions.ConnectionError:
            error_message = "Could not connect to the server"
            if request.is_json:
                return jsonify({'error': error_message}), 500
            return render_template('signup.html', error=error_message)
        except Exception as e:
            print(f"Signup error: {str(e)}")
            error_message = f"An unexpected error occurred: {str(e)}"
            if request.is_json:
                return jsonify({'error': error_message}), 500
            return render_template('signup.html', error=error_message)
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    print(f"Session data in dashboard: {session}")
    if 'user' not in session:
        print("No user in session, redirecting to login")
        return redirect(url_for('login'))
    try:
        user_data = session['user']
        print(f"Rendering dashboard with user data: {user_data}")
        return render_template('dashboard.html', 
                             username=user_data['username'],
                             role=user_data['role'])
    except KeyError as e:
        print(f"KeyError in dashboard: {str(e)}")
        session.clear()
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        session.clear()
        return redirect(url_for('login'))

@app.route('/create-project/<region>', methods=['GET', 'POST'])
def create_project(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Check if user has proper permissions
    if session['user'].get('role') not in ['admin', 'project_manager']:
        return render_template('error.html', message="You don't have permission to create projects")
    
    if request.method == 'POST':
        # Process form data
        try:
            # Get form data
            data = {
                'customer_name': request.form.get('customer_name'),
                'customer_phone': request.form.get('customer_phone'),
                'customer_email': request.form.get('customer_email'),
                'date': request.form.get('date'),
                'po': request.form.get('po'),
                'address': request.form.get('address'),
                'city': request.form.get('city'),
                'subdivision': request.form.get('subdivision'),
                'lot_number': request.form.get('lot_number'),
                'square_footage': request.form.get('square_footage'),
                'notes': request.form.get('notes'),
                'region': region,
                'work_type': request.form.getlist('work_type'),
                'job_cost_type': request.form.getlist('job_cost_type')
            }
            
            # Handle 'other' inputs
            if 'other' in data['work_type']:
                other_work = request.form.get('work_type_other')
                if other_work:
                    data['work_type'].remove('other')
                    data['work_type'].append(other_work)
                    
            if 'other' in data['job_cost_type']:
                other_cost = request.form.get('job_cost_type_other')
                if other_cost:
                    data['job_cost_type'].remove('other')
                    data['job_cost_type'].append(other_cost)

            # Send request to backend
            response = requests.post(
                f'{BACKEND_URL}/api/projects/create',
                json=data
            )
            
            if response.status_code == 201:
                return redirect(url_for('calendar', region=region))
            else:
                error_message = response.json().get('error', 'Failed to create project')
                return render_template('create_project.html', error=error_message, region=region)
                
        except Exception as e:
            print(f"Error creating project: {str(e)}")
            return render_template('create_project.html', error=str(e), region=region)
    
    return render_template('create_project.html', region=region)

@app.route('/import-customers')
def import_customers():
    return render_template('import_customers.html')

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
    
    try:
        # Fetch projects for this region and date from backend
        response = requests.get(f'{BACKEND_URL}/api/projects/{region}')
        if response.status_code == 200:
            all_projects = response.json()
            print(f"Retrieved projects for {region}: {len(all_projects)} total")  # Debug print
            # Filter projects for this date
            projects = [p for p in all_projects if p['date'] == date]
            print(f"Filtered projects for {date}: {len(projects)} found")  # Debug print
        else:
            print(f"Error fetching projects: {response.text}")  # Debug print
            projects = []
    except Exception as e:
        print(f"Exception while fetching projects: {str(e)}")  # Debug print
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

@app.route('/user-management')
def user_management():
    if 'user' not in session:
        print("No user in session, redirecting to login")
        return redirect(url_for('login'))
    
    # Check if user is admin
    print(f"Current user session data: {session['user']}")
    if session['user'].get('role') != 'admin':
        print(f"User role {session['user'].get('role')} is not admin")
        return render_template('error.html', message="You don't have permission to manage users")
    
    try:
        # Get users from backend
        print(f"Making request to {BACKEND_URL}/user-management/users")
        response = requests.get(
            f'{BACKEND_URL}/user-management/users',
            cookies=request.cookies  # Forward cookies to maintain session
        )
        
        print(f"Backend response status: {response.status_code}")
        print(f"Backend response headers: {response.headers}")
        print(f"Backend response content: {response.text}")
        
        if response.status_code == 200:
            users = response.json()
            print(f"Successfully fetched users: {users}")
            
            # Get available roles
            print("Fetching roles...")
            roles_response = requests.get(
                f'{BACKEND_URL}/user-management/roles',
                cookies=request.cookies  # Forward cookies to maintain session
            )
            
            print(f"Roles response status: {roles_response.status_code}")
            print(f"Roles response content: {roles_response.text}")
            
            if roles_response.status_code == 200:
                roles = roles_response.json()
                print(f"Successfully fetched roles: {roles}")
                return render_template('user_management.html', users=users, roles=roles)
            else:
                print(f"Error fetching roles: {roles_response.text}")
                return render_template('user_management.html', error="Error fetching roles", users=[])
        else:
            print(f"Error fetching users: {response.text}")
            return render_template('user_management.html', error="Error fetching users", users=[])
            
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {str(e)}")
        return render_template('user_management.html', error="Could not connect to the server", users=[])
    except Exception as e:
        print(f"Error in user management: {str(e)}")
        return render_template('user_management.html', error=f"An unexpected error occurred: {str(e)}", users=[])

@app.route('/update-user-role/<int:user_id>', methods=['POST'])
def update_user_role(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if session['user'].get('role') != 'admin':
        return render_template('error.html', message="You don't have permission to manage users")
    
    try:
        new_role = request.form.get('role')
        if not new_role:
            return redirect(url_for('user_management', error="Role is required"))
        
        response = requests.put(
            f'{BACKEND_URL}/user-management/users/{user_id}/role',
            json={'role': new_role}
        )
        
        if response.status_code == 200:
            return redirect(url_for('user_management', success="User role updated successfully"))
        else:
            error_message = response.json().get('error', 'Failed to update user role')
            return redirect(url_for('user_management', error=error_message))
            
    except Exception as e:
        print(f"Error updating user role: {str(e)}")
        return redirect(url_for('user_management', error=f"An unexpected error occurred: {str(e)}"))

if __name__ == '__main__':
    app.run(port=5000, debug=True)