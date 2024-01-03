 # Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import os
import json
import logging

from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

instance_metadata_table = boto3.resource('dynamodb').Table(os.environ['INSTANCE_METADATA_TABLE'])
task_metadata_table = boto3.resource('dynamodb').Table(os.environ['TASK_METADATA_TABLE'])

ec2 = boto3.client('ec2')
ecs = boto3.client('ecs')

def paginate(method, **kwargs):
    client = method.__self__

    try:
        paginator = client.get_paginator(method.__name__)
        for page in paginator.paginate(**kwargs).result_key_iters():
            for item in page:
                yield item

    except ClientError as e:
        message = 'Error describing instances: {}'.format(e)
        logger.info(message)
        raise Exception(message)

def describe_instances(instance_ids):
    described_instances = []

    response = paginate(ec2.describe_instances, InstanceIds=instance_ids)

    logger.info(response)

    for item in response:
        for instance in item['Instances']:
            described_instances.append(instance)

    return described_instances

def describe_task_definitions(task_definition_arns):
    described_task_definitions = []

    response = ecs.describe_task_definition(taskDefinition=task_definition_arns)

    logger.info(response)

    for task_definition in response['taskDefinitions']:
        described_task_definitions.append(task_definition)

    return described_task_definitions

def lambda_handler(event, context):

    logger.info(event)

    instance_ids = []
    task_definition_arns = []
    described_instances = []
    described_task_definitions = []

    # Get Inserted Instances and Task Definitions
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            item = record['dynamodb']['NewImage']
            if 'InstanceId' in item:
                instance_id = item['InstanceId']['S']
                instance_ids.append(instance_id)
                logger.info(item)
            elif 'TaskDefinitionArn' in item:
                task_definition_arn = item['TaskDefinitionArn']['S']
                task_definition_arns.append(task_definition_arn)
                logger.info(item)

    # Describe Instances
    if len(instance_ids) > 0:
        described_instances = describe_instances(instance_ids)
        logger.info(described_instances)

    # Describe Task Definitions
    if len(task_definition_arns) > 0:
        described_task_definitions = describe_task_definitions(task_definition_arns)
        logger.info(described_task_definitions)

    # Update Instance Records With Metadata
    for instance in described_instances:
        logger.info(instance)
        try:
            item = {
                'InstanceId': instance['InstanceId'],
                'InstanceType': instance['InstanceType'],
                'InstanceLifecycle': '',
                'AvailabilityZone': instance['Placement']['AvailabilityZone'],
                'Tags': instance['Tags'],
                'InstanceMetadataEnriched': True
            }

            if 'InstanceLifecycle' in instance:
                item['InstanceLifecycle'] = instance['InstanceLifecycle']
            else:
                item['InstanceLifecycle'] = 'on-demand'

            response = instance_metadata_table.update_item(
                Key={
                    'InstanceId': item['InstanceId']
                },
                UpdateExpression="SET #InstanceType = :InstanceType, #InstanceLifecycle = :InstanceLifecycle, #AvailabilityZone = :AvailabilityZone, #Tags = :Tags, #InstanceMetadataEnriched = :InstanceMetadataEnriched",
                ExpressionAttributeNames={
                    '#InstanceType': 'InstanceType',
                    '#InstanceLifecycle': 'InstanceLifecycle',
                    '#AvailabilityZone': 'AvailabilityZone',
                    '#Tags': 'Tags',
                    '#InstanceMetadataEnriched': 'InstanceMetadataEnriched'
                },
                ExpressionAttributeValues={
                    ':InstanceType': item['InstanceType'],
                    ':InstanceLifecycle': item['InstanceLifecycle'],
                    ':AvailabilityZone': item['AvailabilityZone'],
                    ':Tags': item['Tags'],
                    ':InstanceMetadataEnriched': item['InstanceMetadataEnriched']
                },
                ReturnValues="NONE"
            )

            logger.info(response)
        except ClientError as e:
            message = 'Error updating instances in DynamoDB: {}'.format(e)
            logger.info(message)
            raise Exception(message)

    # Update Task Records With Metadata
    for task_definition in described_task_definitions:
        logger.info(task_definition)
        try:
            item = {
                'TaskDefinitionArn': task_definition['taskDefinitionArn'],
                'ContainerDefinitions': task_definition['containerDefinitions'],
                'Tags': task_definition['tags'],
                'TaskMetadataEnriched': True
            }

            response = task_metadata_table.update_item(
                Key={
                    'TaskDefinitionArn': item['TaskDefinitionArn']
                },
                UpdateExpression="SET #ContainerDefinitions = :ContainerDefinitions, #Tags = :Tags, #TaskMetadataEnriched = :TaskMetadataEnriched",
                ExpressionAttributeNames={
                    '#ContainerDefinitions': 'ContainerDefinitions',
                    '#Tags': 'Tags',
                    '#TaskMetadataEnriched': 'TaskMetadataEnriched'
                },
                ExpressionAttributeValues={
                    ':ContainerDefinitions': item['ContainerDefinitions'],
                    ':Tags': item['Tags'],
                    ':TaskMetadataEnriched': item['TaskMetadataEnriched']
                },
                ReturnValues="NONE"
            )

            logger.info(response)
        except ClientError as e:
            message = 'Error updating task definitions in DynamoDB: {}'.format(e)
            logger.info(message)
            raise Exception(message)

    # End
    logger.info('Execution Complete')
    return