import pandas as pd
from sklearn.preprocessing import LabelEncoder

class LogPreprocessor:
    def __init__(self):
        self.le_action = LabelEncoder()
        self.le_country = LabelEncoder()
        self.le_user = LabelEncoder()

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df['Hour'] = df['Timestamp'].dt.hour
        df['DayOfWeek'] = df['Timestamp'].dt.dayofweek

        df['IsFailed'] = (df['Status'] == 'Failed').astype(int)

        df['Action_Encoded'] = self.le_action.fit_transform(df['Action'])
        df['Country_Encoded'] = self.le_country.fit_transform(df['Country'])
        df['User_Encoded'] = self.le_user.fit_transform(df['Username'])

        df = df.sort_values('Timestamp')
        df['IP_Failed_Count_10m'] = df.groupby('IP')['IsFailed'].transform(
            lambda x: x.rolling(10, min_periods=1).sum()
        )
        
        high_risk_actions = ['DeleteBucket', 'AttachRolePolicy', 'DisableLogging', 'CreateIAMUser']
        df['High_Risk_Action'] = df['Action'].isin(high_risk_actions).astype(int)

        return df

    def get_feature_matrix(self, df_processed: pd.DataFrame) -> pd.DataFrame:
        features = [
            'Hour', 'DayOfWeek', 'IsFailed', 'Action_Encoded', 
            'Country_Encoded', 'User_Encoded', 'IP_Failed_Count_10m', 'High_Risk_Action'
        ]
        return df_processed[features]