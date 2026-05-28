"""
ADVANCED MODEL TRAINING MODULE
===============================
Implements state-of-the-art ML techniques:
- Stacking ensemble
- Hyperparameter optimization
- Cross-validation strategies
- Model interpretability (SHAP, LIME)
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold,
    GridSearchCV, RandomizedSearchCV
)
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    ExtraTreesClassifier, AdaBoostClassifier, VotingClassifier,
    StackingClassifier
)
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score,
    matthews_corrcoef, cohen_kappa_score
)
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, mutual_info_classif, RFECV
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV
import joblib
import warnings
warnings.filterwarnings('ignore')

class ModelTrainer:
    """Advanced model training with hyperparameter optimization"""
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.best_model = None
        self.feature_selector = None
        self.scaler = RobustScaler()
        
    def create_stacking_ensemble(self) -> StackingClassifier:
        """Create a stacking ensemble with multiple base models"""
        
        # Base models
        base_models = [
            ('rf', RandomForestClassifier(
                n_estimators=300, max_depth=20, min_samples_split=5,
                min_samples_leaf=2, random_state=self.random_state, n_jobs=-1
            )),
            ('gb', GradientBoostingClassifier(
                n_estimators=300, learning_rate=0.05, max_depth=6,
                subsample=0.8, random_state=self.random_state
            )),
            ('et', ExtraTreesClassifier(
                n_estimators=300, max_depth=20, random_state=self.random_state, n_jobs=-1
            )),
            ('ada', AdaBoostClassifier(
                n_estimators=200, learning_rate=0.1, random_state=self.random_state
            )),
            ('mlp', MLPClassifier(
                hidden_layer_sizes=(200, 100, 50), activation='relu',
                alpha=0.001, random_state=self.random_state, max_iter=1000,
                early_stopping=True, validation_fraction=0.1
            ))
        ]
        
        # Meta classifier
        meta_classifier = LogisticRegression(
            C=0.1, solver='liblinear', random_state=self.random_state
        )
        
        # Create stacking classifier
        stacking = StackingClassifier(
            estimators=base_models,
            final_estimator=meta_classifier,
            cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_state),
            stack_method='predict_proba',
            n_jobs=-1
        )
        
        return stacking
    
    def hyperparameter_tuning(self, X_train, y_train):
        """Perform hyperparameter tuning using RandomizedSearchCV"""
        print("\n[INFO] Performing hyperparameter optimization...")
        
        # Parameter distributions
        param_distributions = {
            'rf__n_estimators': [100, 200, 300, 500],
            'rf__max_depth': [10, 15, 20, 25, None],
            'rf__min_samples_split': [2, 5, 10],
            'rf__min_samples_leaf': [1, 2, 4],
            'gb__n_estimators': [100, 200, 300],
            'gb__learning_rate': [0.01, 0.05, 0.1, 0.2],
            'gb__max_depth': [3, 5, 7, 10],
            'et__n_estimators': [100, 200, 300],
            'et__max_depth': [10, 15, 20, None],
            'ada__n_estimators': [50, 100, 200],
            'ada__learning_rate': [0.01, 0.1, 0.5, 1.0]
        }
        
        # Create base model for tuning
        base_model = self.create_stacking_ensemble()
        
        # Randomized search
        random_search = RandomizedSearchCV(
            base_model,
            param_distributions=param_distributions,
            n_iter=20,
            cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_state),
            scoring='f1',
            n_jobs=-1,
            verbose=1,
            random_state=self.random_state
        )
        
        random_search.fit(X_train, y_train)
        
        print(f"✅ Best parameters: {random_search.best_params_}")
        print(f"✅ Best score: {random_search.best_score_:.4f}")
        
        return random_search.best_estimator_
    
    def select_features(self, X_train, y_train, k=100):
        """Select best features using mutual information"""
        print(f"\n[INFO] Selecting top {k} features...")
        
        self.feature_selector = SelectKBest(
            score_func=mutual_info_classif,
            k=k
        )
        
        X_selected = self.feature_selector.fit_transform(X_train, y_train)
        
        # Get selected feature names
        if hasattr(X_train, 'columns'):
            selected_features = X_train.columns[self.feature_selector.get_support()]
            print(f"✅ Selected features: {list(selected_features[:10])}...")
        
        return X_selected
    
    def train_with_cross_validation(self, X, y, n_splits=10):
        """Train with stratified k-fold cross-validation"""
        print(f"\n[INFO] Training with {n_splits}-fold cross-validation...")
        
        skf = StratifiedKFold(
            n_splits=n_splits,
            shuffle=True,
            random_state=self.random_state
        )
        
        cv_scores = {
            'accuracy': [],
            'precision': [],
            'recall': [],
            'f1': [],
            'auc_roc': []
        }
        
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]
            
            # Train model
            model = self.create_stacking_ensemble()
            model.fit(X_train, y_train)
            
            # Predict
            y_pred = model.predict(X_val)
            y_prob = model.predict_proba(X_val)[:, 1]
            
            # Calculate metrics
            cv_scores['accuracy'].append(accuracy_score(y_val, y_pred))
            cv_scores['precision'].append(precision_score(y_val, y_pred))
            cv_scores['recall'].append(recall_score(y_val, y_pred))
            cv_scores['f1'].append(f1_score(y_val, y_pred))
            cv_scores['auc_roc'].append(roc_auc_score(y_val, y_prob))
            
            print(f"Fold {fold}: F1={cv_scores['f1'][-1]:.4f}, AUC={cv_scores['auc_roc'][-1]:.4f}")
        
        # Print summary
        print("\n📊 Cross-Validation Results:")
        for metric, scores in cv_scores.items():
            print(f"{metric:15}: {np.mean(scores):.4f} (+/- {np.std(scores)*2:.4f})")
        
        return cv_scores
    
    def calculate_advanced_metrics(self, y_true, y_pred, y_prob):
        """Calculate advanced performance metrics"""
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred),
            'recall': recall_score(y_true, y_pred),
            'f1_score': f1_score(y_true, y_pred),
            'auc_roc': roc_auc_score(y_true, y_prob),
            'mcc': matthews_corrcoef(y_true, y_pred),  # Matthews Correlation Coefficient
            'cohen_kappa': cohen_kappa_score(y_true, y_pred)
        }
        
        # Calculate specificity
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        metrics['specificity'] = tn / (tn + fp)
        metrics['npv'] = tn / (tn + fn)  # Negative Predictive Value
        
        return metrics
    
    def save_model_artifacts(self, filepath='model_artifacts.pkl'):
        """Save all model artifacts"""
        artifacts = {
            'best_model': self.best_model,
            'feature_selector': self.feature_selector,
            'scaler': self.scaler
        }
        joblib.dump(artifacts, filepath)
        print(f"✅ Model artifacts saved to {filepath}")
    
    def load_model_artifacts(self, filepath='model_artifacts.pkl'):
        """Load model artifacts"""
        artifacts = joblib.load(filepath)
        self.best_model = artifacts['best_model']
        self.feature_selector = artifacts['feature_selector']
        self.scaler = artifacts['scaler']
        print(f"✅ Model artifacts loaded from {filepath}")