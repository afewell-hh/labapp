#!/usr/bin/env python3
"""
Watchdog Lambda function to terminate labapp metal build instances that exceed max lifetime.

Triggered every 15 minutes by EventBridge, this function:
1. Scans for EC2 instances with tags: Project=labapp, AutoDelete=true
2. Calculates instance age from launch time
3. Terminates instances older than MAX_LIFETIME_HOURS
4. Updates DynamoDB with termination status
5. Sends SNS notifications on forced termination
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

import boto3
from botocore.exceptions import ClientError


# Environment variables
MAX_LIFETIME_HOURS = int(os.environ.get('MAX_LIFETIME_HOURS', '3'))
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# AWS clients
ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main handler for watchdog Lambda.

    Args:
        event: EventBridge scheduled event
        context: Lambda context

    Returns:
        dict: Execution summary
    """
    print(f"Watchdog execution started at {datetime.now(timezone.utc).isoformat()}")
    print(f"MAX_LIFETIME_HOURS: {MAX_LIFETIME_HOURS}")

    results = {
        'checked': 0,
        'terminated': 0,
        'errors': []
    }

    try:
        # Find all labapp build instances with AutoDelete tag
        instances = find_auto_delete_instances()
        results['checked'] = len(instances)

        print(f"Found {len(instances)} instances to check")

        for instance in instances:
            try:
                if should_terminate(instance):
                    terminate_instance(instance)
                    results['terminated'] += 1
                else:
                    instance_id = instance['InstanceId']
                    age_hours = get_instance_age_hours(instance)
                    print(f"Instance {instance_id} is {age_hours:.1f} hours old (within limit)")

            except Exception as e:
                error_msg = f"Error processing instance {instance.get('InstanceId', 'unknown')}: {str(e)}"
                print(error_msg)
                results['errors'].append(error_msg)

        print(f"Watchdog execution completed: {results}")
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }

    except Exception as e:
        error_msg = f"Fatal error in watchdog: {str(e)}"
        print(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_msg,
                'results': results
            })
        }


def find_auto_delete_instances() -> List[Dict[str, Any]]:
    """
    Find all EC2 instances with Project=labapp and AutoDelete=true tags.

    Returns:
        list: Running instances matching criteria
    """
    try:
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'tag:Project', 'Values': ['labapp']},
                {'Name': 'tag:AutoDelete', 'Values': ['true']},
                {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
            ]
        )

        instances = []
        for reservation in response['Reservations']:
            instances.extend(reservation['Instances'])

        return instances

    except ClientError as e:
        print(f"Error describing instances: {e}")
        raise


def should_terminate(instance: Dict[str, Any]) -> bool:
    """
    Check if instance should be terminated based on age.

    Args:
        instance: EC2 instance dict

    Returns:
        bool: True if instance should be terminated
    """
    age_hours = get_instance_age_hours(instance)
    instance_id = instance['InstanceId']

    if age_hours > MAX_LIFETIME_HOURS:
        print(f"Instance {instance_id} is {age_hours:.1f} hours old (limit: {MAX_LIFETIME_HOURS}h) - TERMINATING")
        return True

    return False


def get_instance_age_hours(instance: Dict[str, Any]) -> float:
    """
    Calculate instance age in hours.

    Args:
        instance: EC2 instance dict

    Returns:
        float: Instance age in hours
    """
    launch_time = instance['LaunchTime']
    now = datetime.now(timezone.utc)

    # Ensure launch_time is timezone-aware
    if launch_time.tzinfo is None:
        launch_time = launch_time.replace(tzinfo=timezone.utc)

    age = now - launch_time
    return age.total_seconds() / 3600


def terminate_instance(instance: Dict[str, Any]) -> None:
    """
    Terminate instance and associated resources.

    Args:
        instance: EC2 instance dict
    """
    instance_id = instance['InstanceId']
    build_id = get_tag_value(instance, 'BuildID')
    age_hours = get_instance_age_hours(instance)

    print(f"Terminating instance {instance_id} (BuildID: {build_id}, Age: {age_hours:.1f}h)")

    try:
        # Terminate instance
        ec2.terminate_instances(InstanceIds=[instance_id])
        print(f"Instance {instance_id} termination initiated")

        # Update DynamoDB with forced termination status
        if build_id:
            update_build_state(build_id, instance_id, age_hours)

        # Send SNS notification
        send_termination_notification(instance_id, build_id, age_hours)

    except ClientError as e:
        error_msg = f"Error terminating instance {instance_id}: {e}"
        print(error_msg)
        raise


def get_tag_value(instance: Dict[str, Any], tag_name: str) -> str:
    """
    Get tag value from instance.

    Args:
        instance: EC2 instance dict
        tag_name: Tag key to find

    Returns:
        str: Tag value or empty string
    """
    tags = instance.get('Tags', [])
    for tag in tags:
        if tag['Key'] == tag_name:
            return tag['Value']
    return ''


def update_build_state(build_id: str, instance_id: str, age_hours: float) -> None:
    """
    Update DynamoDB with forced termination status.

    Args:
        build_id: Build identifier
        instance_id: EC2 instance ID
        age_hours: Instance age in hours
    """
    try:
        table.update_item(
            Key={'BuildID': build_id},
            UpdateExpression='SET #status = :status, ForcedTermination = :forced, CompletionTime = :completion, ErrorMessage = :error',
            ExpressionAttributeNames={
                '#status': 'Status'
            },
            ExpressionAttributeValues={
                ':status': 'terminated',
                ':forced': True,
                ':completion': datetime.now(timezone.utc).isoformat(),
                ':error': f'Force terminated by watchdog after {age_hours:.1f} hours (limit: {MAX_LIFETIME_HOURS}h)'
            }
        )
        print(f"Updated DynamoDB state for build {build_id}")

    except ClientError as e:
        print(f"Error updating DynamoDB for build {build_id}: {e}")
        # Don't raise - termination is more important than DynamoDB update


def send_termination_notification(instance_id: str, build_id: str, age_hours: float) -> None:
    """
    Send SNS notification about forced termination.

    Args:
        instance_id: EC2 instance ID
        build_id: Build identifier
        age_hours: Instance age in hours
    """
    try:
        subject = f"[CRITICAL] labapp build instance force-terminated: {build_id}"

        message = f"""
CRITICAL: Labapp metal build instance was force-terminated by watchdog

Instance ID: {instance_id}
Build ID: {build_id}
Instance Age: {age_hours:.1f} hours
Lifetime Limit: {MAX_LIFETIME_HOURS} hours
Termination Time: {datetime.now(timezone.utc).isoformat()}

Reason: Instance exceeded maximum lifetime limit

This likely indicates a hung build or configuration issue. Please investigate:
1. Check CloudWatch logs: /labapp/metal-builds/{build_id}
2. Review DynamoDB table: {DYNAMODB_TABLE}
3. Check for partial build artifacts in S3
4. Verify Packer build configuration

The instance and associated resources have been terminated to prevent runaway costs.

Cost impact: ~${age_hours * 4.40:.2f} (estimated)
"""

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

        print(f"Sent SNS notification for instance {instance_id}")

    except ClientError as e:
        print(f"Error sending SNS notification: {e}")
        # Don't raise - termination is more important than notification


if __name__ == '__main__':
    # For local testing
    test_event = {}
    test_context = type('Context', (), {'aws_request_id': 'test'})()
    result = lambda_handler(test_event, test_context)
    print(json.dumps(result, indent=2))
