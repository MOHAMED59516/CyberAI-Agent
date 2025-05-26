import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report
from joblib import dump

# توليد بيانات اصطناعية لحركة الشبكة
def generate_synthetic_data(n_samples=1000):
    np.random.seed(42)
    
    data = []
    for _ in range(n_samples):
        # ميزات
        packet_length = np.random.randint(20, 1500)  # طول الباكيت
        ttl = np.random.randint(1, 128)              # TTL
        protocol = np.random.choice([1, 6, 17])      # ICMP=1, TCP=6, UDP=17
        src_port = np.random.randint(1024, 65535)
        dst_port = np.random.randint(1, 1024)
        packet_count = np.random.randint(1, 20)      # عدد الباكيتات من نفس المصدر
        
        # تسمية نوع الحركة: 0 = عادي، 1 = هجوم
        # قاعدة بسيطة: لو طول الباكيت عالي و packet_count عالي ممكن تكون هجوم
        label = 1 if (packet_length > 1000 and packet_count > 10) else 0
        
        data.append([packet_length, ttl, protocol, src_port, dst_port, packet_count, label])
    
    columns = ["packet_length", "ttl", "protocol", "src_port", "dst_port", "packet_count", "label"]
    return pd.DataFrame(data, columns=columns)

# توليد البيانات
df = generate_synthetic_data(2000)

# تقسيم البيانات
X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# موديل Random Forest
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

rf = RandomForestClassifier(random_state=42)

param_grid = {
    'n_estimators': [50, 100],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5]
}

grid_search = GridSearchCV(rf, param_grid, cv=3, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

best_model = grid_search.best_estimator_

# التقييم
y_pred = best_model.predict(X_test)
print(classification_report(y_test, y_pred))

# حفظ الموديل
dump(best_model, "ai_model.pkl")
print("تم حفظ الموديل المحسن ai_model.pkl")
