import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_cloud_logs(num_records=10000, save_path="dataset/cloud_logs.csv"):
    np.random.seed(42)
    random.seed(42)

    users = ["admin", "dev_user1", "dev_user2", "analyst_alice", "service_account_ci", "intern_bob"]
    normal_actions = ["Login", "ReadS3Bucket", "DescribeInstances", "ListUsers", "PutObject"]
    
    countries = ["India", "United States", "Germany", "Japan", "United Kingdom", "Russia", "China", "Brazil"]
    country_weights = [0.45, 0.25, 0.10, 0.05, 0.05, 0.04, 0.04, 0.02]

    base_time = datetime(2026, 7, 1, 0, 0, 0)
    data = []

    for i in range(num_records):
        timestamp = base_time + timedelta(seconds=i * random.randint(15, 45))
        username = random.choices(users, weights=[0.1, 0.25, 0.25, 0.2, 0.1, 0.1])[0]
        
        is_attack = random.random() < 0.08  # ~8% malicious activity
        
        if is_attack:
            attack_type = random.choice(["brute_force", "suspicious_deletion", "impossible_travel", "iam_tamper"])
            if attack_type == "brute_force":
                action = "Login"
                status = "Failed"
                country = random.choice(["Russia", "China", "Brazil"])
                ip = f"45.81.{random.randint(1,255)}.{random.randint(1,255)}"
            elif attack_type == "suspicious_deletion":
                action = "DeleteBucket"
                status = "Success"
                country = random.choice(["Russia", "China"])
                ip = f"185.220.{random.randint(1,255)}.{random.randint(1,255)}"
            elif attack_type == "impossible_travel":
                action = "Login"
                status = "Success"
                country = random.choice(["Russia", "China"])
                ip = f"91.240.{random.randint(1,255)}.{random.randint(1,255)}"
            else:
                action = "AttachRolePolicy"
                status = "Success"
                country = "United States"
                ip = f"192.168.1.{random.randint(10, 100)}"
        else:
            action = random.choices(normal_actions, weights=[0.3, 0.3, 0.2, 0.1, 0.1])[0]
            status = "Success" if random.random() > 0.05 else "Failed"
            country = random.choices(countries, weights=country_weights)[0]
            ip = f"192.168.1.{random.randint(1, 50)}" if country in ["India", "United States"] else f"10.0.0.{random.randint(1, 100)}"

        data.append({
            "LogID": 1000 + i,
            "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Username": username,
            "Action": action,
            "IP": ip,
            "Country": country,
            "Status": status
        })

    df = pd.DataFrame(data)
    df.to_csv(save_path, index=False)
    return df
    