import botocore.config
from botocore.exceptions import ClientError
import boto3
import os
from flask import request, jsonify
from app.model import TodoItem
from . import tasks_bp

session = boto3.Session(profile_name='default')

# Initialize the DynamoDB resource
dynamodb = session.resource('dynamodb')

# Define the table name
table_name = 'to-do-list-storage'  # Replace with your desired table name


table = dynamodb.Table(table_name)





@tasks_bp.route('/api/tasks', methods=['POST'])
def handle_post():
    if request.method == 'POST':
        data = request.json
        try:
            dt = data.get('dt', '')
            task_id = data.get('task_id', 0) 
            title = data.get('title', '')  
            description = data.get('description', '') 
            
            
            todo = TodoItem(
                task_id=task_id,
                dt=dt,
                title=title,
                description=description,                
                is_completed=data.get('is_completed', False)
            )
            table.put_item(Item=todo.to_dict())
            return jsonify({'message': 'Task created successfully'}), 201
        except ClientError as e:
            return jsonify({'error': 'Failed to create task', 'details': str(e)}), 500
   

@tasks_bp.route('/api/tasks', methods=['GET'])
def handle_get():
    if request.method == 'GET':
        try:
            todos = table.scan()['Items']
            return jsonify(todos)
        except ClientError as e:
            return jsonify({'error': 'Failed to retrieve tasks', 'details': str(e)}), 500

@tasks_bp.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    data = request.json

    try:
        existing_task = table.get_item(Key={'task_id': task_id})['Item']
    except KeyError:
        return jsonify({'error': 'Task not found'}), 404

    for key, value in data.items():
        existing_task[key] = value

    table.put_item(Item=existing_task)

    return jsonify({'message': 'Task updated successfully'})

@tasks_bp.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    try:
        existing_task = table.get_item(Key={'task_id': task_id})['Item']
    except KeyError:
        return jsonify({'error': 'Task not found'}), 404

    table.delete_item(Key={'task_id': task_id})

    return jsonify({'message': 'Task deleted successfully'})

@tasks_bp.route('/api/tasks/delete-all', methods=['POST'])
def delete_all_tasks():
    try:
        scan_result = table.scan()
        items = scan_result.get('Items', [])
        for item in items:
            table.delete_item(Key={'task_id': item['task_id']})
        return jsonify({'message': 'All tasks deleted successfully'}), 200
    except ClientError as e:
        return jsonify({'error': 'Failed to delete tasks', 'details': str(e)}), 500

@tasks_bp.route('/api/tasks/delete-completed', methods=['POST'])
def delete_completed_tasks():
    try:
        scan_result = table.scan()
        items = scan_result.get('Items', [])
        for item in items:
            if item['is_completed'] == True:
                table.delete_item(Key={'task_id': item['task_id']})
        return jsonify({'message': 'All completed tasks deleted successfully'}), 200
    except ClientError as e:
        return jsonify({'error': 'Failed to delete tasks', 'details': str(e)}), 500