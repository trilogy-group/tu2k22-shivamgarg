import boto3

file_name = "images.txt"
bucket = "shivamgarg"
Credentials = {
        "AccessKeyId": "ASIAUCMU474JG7QQ7VVL",
        "SecretAccessKey": "1EvFxcmyua4pdpNn2UvnCwfZGpxxRbN9pNJToSZt",
        "SessionToken": "FwoGZXIvYXdzECMaDD27QtVpfujbrTajZyK5AawMgAQB5xOwnZOyhBbvzCjrkrjEf5Xl+mAhVcniZcUmXlWl2xWwpc4zJcmIowja+95JP3rz8CrVNIkC1TtbF5F+AW0G0vXP15TiBqpSsfSswXniHiAUwTWS71/CQhQrvPqyErxWeAcSZX3CrpbxdLxH+3VD0fTwmZJQZWC1pNwMC9JPEiZkSu/rZHbSHyNL05PwGW3GrZcJiFoeUryT4XqzHlkGrQPmdN25slMgluXOa/urIZHkbg46KPuV2pcGMi1vC28srPNaaRE6mollPuWx0obYFFzdfLhHiefCYNxyN64DWB38hPxuqgJ3tMo=",
        "Expiration": "2022-08-12T18:16:43+00:00"
}


s3 = boto3.client('s3',
            aws_access_key_id=Credentials['AccessKeyId'],
            aws_secret_access_key=Credentials['SecretAccessKey'],
            aws_session_token=Credentials['SessionToken']
        )
with open(file_name, "rb") as f:
    s3.upload_fileobj(f, "shivamgarg", "dummy")
