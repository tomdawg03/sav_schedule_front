from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_login import login_required
import requests
import json
import csv

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Global cache for customer data
CUSTOMER_CACHE = []
def load_customer_cache():
    global CUSTOMER_CACHE
    try:
        with open('../sav_schedule_back/data/cust_list.csv', 'r') as file:
            reader = csv.reader(file)
            headers = next(reader)
            customer_idx = headers.index('Customer')
            last_name_idx = headers.index('Last_Name')
            phone_idx = headers.index('Phone')
            email_idx = headers.index('Main_Email')
            
            CUSTOMER_CACHE = [{
                'name': f"{row[customer_idx]} {row[last_name_idx]}".strip(),
                'phone': row[phone_idx].strip(),
                'email': row[email_idx].strip()
            } for row in reader if len(row) >= max(customer_idx, last_name_idx, phone_idx, email_idx) + 1]
    except Exception as e:
        print(f"Error loading customer cache: {str(e)}")
        CUSTOMER_CACHE = []

BACKEND_URL = 'http://localhost:5001'

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
    if 'user' in session:
        try:
            # Validate token with backend
            token = session['user'].get('token')
            if not token:
                print("No token in session at index")
                session.clear()
                return render_template('index.html')
                
            print(f"Validating token at index: {token[:10]}...")
            response = requests.get(
                f'{BACKEND_URL}/auth/validate',
                headers={'Authorization': f"Bearer {token}"}
            )
            
            print(f"Validation response status: {response.status_code}")
            print(f"Validation response content: {response.text}")
            
            if response.ok:
                return redirect(url_for('dashboard'))
            else:
                print("Token validation failed, clearing session")
                session.clear()
                return render_template('index.html')
        except Exception as e:
            print(f"Error validating session: {str(e)}")
            session.clear()
            return render_template('index.html')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            print(f"Attempting login...")
            response = requests.post(
                f'{BACKEND_URL}/auth/login',
                data={
                    'username': request.form.get('username'),
                    'password': request.form.get('password')
                }
            )
            
            print(f"Login response status: {response.status_code}")
            print(f"Login response content: {response.text}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    user_data = data.get('user', {})
                    token = data.get('token')  # Get token from root level
                    
                    if not token:
                        print("No token received from backend")
                        return render_template('login.html', error="Authentication failed")
                        
                    print(f"Token received: {token[:10]}...")
                    session['user'] = {
                        'id': user_data.get('id'),
                        'username': user_data.get('username'),
                        'email': user_data.get('email'),
                        'role': user_data.get('role'),
                        'token': token
                    }
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
        except Exception as e:
            print(f"Login error: {str(e)}")
            return render_template('login.html', error='An error occurred')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Forward the request to the backend
            response = requests.post(
                f'{BACKEND_URL}/auth/signup',
                json=request.get_json(),
                headers={'Content-Type': 'application/json'}
            )
            return response.json(), response.status_code
        except Exception as e:
            print(f"Error in signup: {str(e)}")
            return jsonify({'error': 'Error creating account'}), 500
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        print("No user in session at dashboard")
        return redirect(url_for('login'))
    try:
        print(f"Dashboard accessed with token: {session['user'].get('token', 'NO_TOKEN')[:10]}...")
        user_data = session['user']
        return render_template('dashboard.html', 
                             username=user_data['username'],
                             role=user_data['role'])
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        # Don't clear session yet
        print(f"Session data at dashboard error: {session.get('user', 'NO_USER')}")
        return redirect(url_for('login'))

@app.route('/create-project/<region>', methods=['GET', 'POST'])
def create_project(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if session['user'].get('role') not in ['admin', 'project_manager']:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            response = requests.post(
                f'{BACKEND_URL}/projects/{region}',
                headers={'Authorization': f"Bearer {session['user']['token']}"},
                json=data
            )
            
            if response.ok:
                # Store the project data in session for confirmation page
                session['latest_project'] = data
                session['latest_project']['region'] = region
                session['latest_project']['is_update'] = False  # Indicate this is a new project
                return jsonify({
                    'success': True,
                    'message': 'Project created successfully'
                })
            else:
                error_message = response.json().get('error', 'Failed to create project')
                return jsonify({'error': error_message}), response.status_code
        except Exception as e:
            print(f"Error in create_project: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    return render_template('create_project.html', 
                         region=region,
                         job_cost_types=JOB_COST_TYPES,
                         work_types=WORK_TYPES)

@app.route('/confirmation/<region>', methods=['GET'])
def confirmation(region):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        # First try to get project from session
        if 'latest_project' in session:
            project_data = session.pop('latest_project')  # Remove from session after use
            is_update = project_data.pop('is_update', False)  # Get and remove is_update flag
            message = "Project Updated Successfully!" if is_update else "Project Created Successfully!"
            return render_template('confirmation.html', 
                                project=project_data, 
                                region=region,
                                username=session['user']['username'],
                                role=session['user']['role'],
                                message=message)
        
        # Fallback to API call if not in session
        print("Fetching latest project for confirmation...")
        response = requests.get(
            f'{BACKEND_URL}/projects/{region}/latest',
            headers={'Authorization': f"Bearer {session['user']['token']}"}
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.ok:
            project_data = response.json()
            print(f"Project data received: {project_data}")
            return render_template('confirmation.html', 
                                project=project_data, 
                                region=region,
                                username=session['user']['username'],
                                role=session['user']['role'],
                                message="Project Created Successfully!")
        else:
            print(f"Error fetching latest project: {response.text}")
            return render_template('error.html', 
                                message="Could not load project details. Please check the calendar to verify your project was created.",
                                region=region)
    except Exception as e:
        print(f"Error in confirmation route: {str(e)}")
        return render_template('error.html', 
                            message="An error occurred while loading the confirmation page. Please check the calendar to verify your project was created.",
                            region=region)

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
        token = session['user'].get('token')
        if not token:
            return redirect(url_for('login'))
            
        headers = {'Authorization': f"Bearer {token}"}
        response = requests.get(f'{BACKEND_URL}/projects/{region}', headers=headers)
        
        if response.status_code == 200:
            projects = response.json()
            return render_template('calendar.html',
                                region=region,
                                username=session['user']['username'],
                                role=session['user']['role'],
                                projects=projects,
                                projects_json=json.dumps(projects))
        else:
            return render_template('calendar.html',
                                region=region,
                                username=session['user']['username'],
                                role=session['user']['role'],
                                projects=[],
                                projects_json='[]')
    except Exception as e:
        print(f"Error in calendar route: {str(e)}")
        return redirect(url_for('login'))

@app.route('/user-management')
def user_management():
    print("Accessing user management route...")
    print(f"Session contents: {session}")
    
    if 'user' not in session:
        print("No user in session, redirecting to login")
        return redirect(url_for('login'))
    
    user_data = session['user']
    print(f"User data from session: {user_data}")
    
    if user_data.get('role') != 'admin':
        print(f"User role {user_data.get('role')} is not admin")
        return render_template('error.html', message="You don't have permission to manage users")
    
    try:
        # Get token from session
        token = user_data.get('token')
        if not token:
            print("No token found in session")
            return redirect(url_for('login'))

        print("Validating token before making user management request...")
        # Validate token
        headers = {'Authorization': f'Bearer {token}'}
        validate_response = requests.get(f'{BACKEND_URL}/auth/validate', headers=headers)
        print(f"Validation response: {validate_response.status_code}")
        
        if validate_response.status_code != 200:
            print("Token validation failed, redirecting to login")
            session.clear()
            return redirect(url_for('login'))

        # Make request to get users
        print("Getting users list...")
        response = requests.get(f'{BACKEND_URL}/auth/users', headers=headers)
        print(f"Users response: {response.status_code}")
        print(f"Users response content: {response.text}")
        
        # Define available roles
        roles = [
            {'name': 'admin', 'display_name': 'Admin'},
            {'name': 'project_manager', 'display_name': 'Project Manager'},
            {'name': 'viewer', 'display_name': 'Viewer'}
        ]
        
        if response.status_code == 200:
            users = response.json()
            print("Successfully fetched users, rendering template...")
            print(f"Users data: {users}")  # Add this line to debug
            return render_template('user_management.html', 
                                users=users,
                                username=user_data['username'],
                                role=user_data['role'],
                                roles=roles)
        else:
            print(f"Error fetching users: {response.status_code}")
            print(f"Error response: {response.text}")
            flash('Error fetching users', 'error')
            return render_template('user_management.html', 
                                users=[],
                                username=user_data['username'],
                                role=user_data['role'],
                                roles=roles)
            
    except Exception as e:
        print(f"Exception in user management: {str(e)}")
        flash('Error accessing user management', 'error')
        return render_template('user_management.html', 
                            users=[],
                            username=user_data['username'],
                            role=user_data['role'],
                            roles=roles)

@app.route('/user/<int:user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if session['user'].get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        token = session['user'].get('token')
        if not token:
            return jsonify({'error': 'No token found'}), 401

        headers = {'Authorization': f'Bearer {token}'}
        data = request.get_json()
        
        response = requests.put(
            f'{BACKEND_URL}/auth/user/{user_id}/role',
            headers=headers,
            json=data
        )
        
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error updating user role: {str(e)}")
        return jsonify({'error': 'Failed to update user role'}), 500

@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if session['user'].get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        token = session['user'].get('token')
        if not token:
            return jsonify({'error': 'No token found'}), 401

        headers = {'Authorization': f'Bearer {token}'}
        response = requests.delete(
            f'{BACKEND_URL}/auth/user/{user_id}',
            headers=headers
        )
        
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/analytics')
def analytics():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Allow both admin and project_manager roles
    if session['user'].get('role') not in ['admin', 'project_manager']:
        return render_template('error.html', message="You don't have permission to view analytics")
    
    try:
        token = session['user'].get('token')
        if not token:
            return redirect(url_for('login'))
            
        response = requests.get(
            f'{BACKEND_URL}/analytics/monthly',
            headers={'Authorization': f"Bearer {token}"}
        )
        
        if response.ok:
            analytics_data = response.json()
            return render_template('analytics.html', analytics_data=analytics_data)
        else:
            return render_template('error.html', message="Failed to fetch analytics data")
            
    except Exception as e:
        print(f"Error in analytics route: {str(e)}")
        return render_template('error.html', message="An error occurred while fetching analytics")

@app.route('/day-view/<region>/<date>')
def day_view(region, date):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    try:
        token = session['user'].get('token')
        if not token:
            return redirect(url_for('login'))
            
        headers = {'Authorization': f"Bearer {token}"}
        print(f"Fetching projects for {region} on {date}")
        response = requests.get(
            f'{BACKEND_URL}/projects/{region}/date/{date}',
            headers=headers
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.status_code == 200:
            projects = response.json()
            return render_template('day_view.html',
                                region=region,
                                date=date,
                                projects=projects,
                                username=session['user']['username'],
                                role=session['user']['role'])
        else:
            print(f"Error response: {response.text}")
            return render_template('day_view.html',
                                region=region,
                                date=date,
                                projects=[],
                                username=session['user']['username'],
                                role=session['user']['role'])
    except Exception as e:
        print(f"Error in day view route: {str(e)}")
        return redirect(url_for('calendar', region=region))

@app.route('/edit-project/<region>/<project_id>', methods=['GET', 'PUT'])
def edit_project(region, project_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    try:
        token = session['user'].get('token')
        if not token:
            return redirect(url_for('login'))
            
        headers = {'Authorization': f"Bearer {token}"}
        
        if request.method == 'PUT':
            data = request.get_json()
            response = requests.put(
                f'{BACKEND_URL}/projects/{region}/{project_id}',
                headers=headers,
                json=data
            )
            
            if response.ok:
                # Store the project data and update flag in session for confirmation page
                session['latest_project'] = data
                session['latest_project']['region'] = region
                session['latest_project']['is_update'] = True  # Indicate this is an update
                return jsonify({'success': True, 'message': 'Project updated successfully'})
            else:
                error_message = response.json().get('error', 'Failed to update project')
                return jsonify({'error': error_message}), response.status_code
        
        # GET request
        response = requests.get(
            f'{BACKEND_URL}/projects/{region}/{project_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            project = response.json()
            return render_template('create_project.html',
                                region=region,
                                project=project,
                                job_cost_types=JOB_COST_TYPES,
                                work_types=WORK_TYPES,
                                edit_mode=True)
        else:
            return render_template('error.html', message="Project not found")
    except Exception as e:
        print(f"Error in edit project route: {str(e)}")
        return render_template('error.html', message="An error occurred while loading the project")

@app.route('/search-customers', methods=['GET'])
def search_customers():
    try:
        query = request.args.get('q', '').lower()
        if not query:
            return jsonify([])
            
        # Search in memory cache
        results = [
            customer for customer in CUSTOMER_CACHE
            if query in customer['name'].lower() or query in customer['phone'].lower()
        ][:10]  # Limit to 10 results
        
        return jsonify(results)
    except Exception as e:
        print(f"Error searching customers: {str(e)}")
        return jsonify([])

@app.route('/user/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if session['user'].get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        token = session['user'].get('token')
        if not token:
            return jsonify({'error': 'No token found'}), 401

        headers = {'Authorization': f'Bearer {token}'}
        data = request.get_json()
        
        response = requests.put(
            f'{BACKEND_URL}/auth/user/{user_id}',
            headers=headers,
            json=data
        )
        
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error updating user: {str(e)}")
        return jsonify({'error': 'Failed to update user'}), 500

if __name__ == '__main__':
    load_customer_cache()  # Load customers when app starts
    app.run(port=5000, debug=True)