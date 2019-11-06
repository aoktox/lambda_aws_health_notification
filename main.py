import logging
import boto3
import jinja2
import slack

# setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')
rds_client = boto3.client('rds')


def get_ec2_tags(instanceIds):
    print("Getting EC2 Instances Tags")
    instance_tags = []
    try:
        reservations = ec2_client.describe_instances(
            InstanceIds=instanceIds
        )
        for reservation in reservations['Reservations']:
            for instances in reservation['Instances']:
                tag = {}
                tag['InstanceId'] = instances['InstanceId']
                for instance_tag in instances['Tags']:
                    if instance_tag['Key'] == "ProductDomain":
                        tag['ProductDomain'] = instance_tag['Value']
                    if instance_tag['Key'] == "Service":
                        tag['Service'] = instance_tag['Value']
                    if instance_tag['Key'] == "Cluster":
                        tag['Cluster'] = instance_tag['Value']
                instance_tags.append(tag)
    except Exception as e:
        print(e)
    print(instance_tags)
    return instance_tags


def get_rds_arn(dbInstances):
    print("Getting RDS DBInstances ARN")
    dbInstancesArn = []
    try:
        rdsDbInstances = rds_client.describe_db_instances(
            Filters=[
                {
                    'Name': 'db-instance-id',
                    'Values': dbInstances
                }
            ]
        )
        for rdsDbInstance in rdsDbInstances['DBInstances']:
            dbInstancesArn.append(rdsDbInstance['DBInstanceArn'])
    except Exception as err:
        print(err)
    return dbInstancesArn


def get_rds_tags(dbInstances):
    print("Getting RDS DBInstances Tags")
    dbInstanceArns = get_rds_arn(dbInstances)
    db_instance_tags = []
    i = 0
    for dbInstanceArn in dbInstanceArns:
        try:
            reservations = rds_client.list_tags_for_resource(
                ResourceName=dbInstanceArn
            )
            tag = {}
            tag['InstanceId'] = dbInstances[i]
            for instance_tag in reservations['TagList']:
                if instance_tag['Key'] == "ProductDomain":
                    tag['ProductDomain'] = instance_tag['Value']
                if instance_tag['Key'] == "Service":
                    tag['Service'] = instance_tag['Value']
                if instance_tag['Key'] == "Cluster":
                    tag['Cluster'] = instance_tag['Value']
            db_instance_tags.append(tag)
        except Exception as err:
            print(err)
        i = i + 1
    return db_instance_tags


def get_affected_resources(service, resources):
    affected_resources = []
    if "EC2" == service:
        affected_resources = get_ec2_tags(resources)
    elif "RDS" == service:
        affected_resources = get_rds_tags(resources)

    # if affected_resources is empty, return raw resources
    return affected_resources if affected_resources else resources


def get_account_alias():
    try:
        return "{} | ".format(str(boto3.client('iam').list_account_aliases()['AccountAliases'][0]).upper())
    except:
        return ""


def create_slack_client():
    slackChannel = boto3.client('ssm').get_parameter(
        Name="/tvlk-secret/health_notif/devops/slack_channel",
        WithDecryption=True
    )['Parameter']['Value']

    slackToken = boto3.client('ssm').get_parameter(
        Name="/tvlk-secret/health_notif/devops/slack_token",
        WithDecryption=True
    )['Parameter']['Value']

    return [slack.WebClient(token=slackToken), slackChannel]


def lambda_handler(event, context):
    """
    main lambda function for handling events of AWS infrastructure health notification
    """
    logger.info('Event: ' + str(event))

    service = event["detail"]["service"]
    eventTypeCategory = event["detail"]["eventTypeCategory"]
    eventDescription = event['detail'][
        'eventDescription'][0]['latestDescription']
    resources = event['resources']
    affectedResources = get_affected_resources(service, resources)
    template = jinja2.Environment(
        loader=jinja2.FileSystemLoader("./")
    ).get_template("postTemplate.j2")
    message = template.render(
        eventDescription=eventDescription.replace("\\n", "\n"),
        resources=affectedResources
    )
    postFileandTitle = "{}Amazon {}".format(get_account_alias(), service.upper())
    if eventTypeCategory == "scheduledChange":
        postFileandTitle = postFileandTitle + " Scheduled Maintenance"
    elif eventTypeCategory == "issue":
        postFileandTitle = postFileandTitle + " Issue"
    elif eventTypeCategory == "accountNotification":
        postFileandTitle = postFileandTitle + " Account Notification"
    try:
        sc, slack_channel = create_slack_client()

        response = sc.files_upload(
            channels=slack_channel,
            content=message,
            filetype="post",
            filename=postFileandTitle,
            title=postFileandTitle
        )
        print(response['response_metadata'])

    except Exception as error:
        print(error)


if __name__ == "__main__":
    with open("event_example.json") as json_file:
        import json

        data = json.load(json_file)
        lambda_handler(data, "context")
