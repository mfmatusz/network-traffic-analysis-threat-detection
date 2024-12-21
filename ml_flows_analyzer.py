import click
import pandas as pd
import numpy as np
from nfstream import NFStreamer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

def prepare_data(normal_pcap, malicious_pcap=None, prediction_mode=False):
    """Prepare data from PCAP files"""
    # Load normal traffic
    normal_flows = NFStreamer(source=normal_pcap, statistical_analysis=True).to_pandas()
    
    if not prediction_mode:
        normal_flows['label'] = 0
        if malicious_pcap:
            # Load malicious traffic
            malicious_flows = NFStreamer(source=malicious_pcap, statistical_analysis=True).to_pandas()
            malicious_flows['label'] = 1
            data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        else:
            data = normal_flows
    else:
        data = normal_flows

    # Remove columns with single value or missing values
    for col in data.columns:
        if data[col].nunique() == 1 or data[col].isnull().any():
            data.drop(col, inplace=True, axis=1)

    # Select only numeric columns
    data = data.select_dtypes(include=[np.number])
    
    # Select important features
    selected_features = [
        'bidirectional_packets', 'bidirectional_bytes',
        'src2dst_packets', 'dst2src_packets',
        'src2dst_bytes', 'dst2src_bytes',
        'bidirectional_duration_ms'
    ]
    
    # Add protocol if available
    if 'protocol' in data.columns:
        selected_features.append('protocol')
        
    # Keep only selected features (and label if not in prediction mode)
    features = [f for f in selected_features if f in data.columns]
    if not prediction_mode:
        features = features + ['label']
    data = data[features]
    
    return data

def train_model(X_train, y_train):
    """Train the model with hyperparameter tuning"""
    # Define parameter grid for GridSearch
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'class_weight': ['balanced', 'balanced_subsample']
    }

    # Initialize base model
    base_model = RandomForestClassifier(random_state=42)

    # Perform GridSearch
    grid_search = GridSearchCV(
        estimator=base_model,
        param_grid=param_grid,
        cv=5,
        scoring='f1',
        n_jobs=-1
    )

    # Fit the model
    grid_search.fit(X_train, y_train)
    
    return grid_search.best_estimator_, grid_search.best_params_

def evaluate_model(model, X_test, y_test):
    """Evaluate the model and display results"""
    predictions = model.predict(X_test)
    
    # Calculate and plot confusion matrix
    cm = confusion_matrix(y_test, predictions)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    # Calculate and plot ROC curve
    proba = model.predict_proba(X_test)
    fpr, tpr, _ = roc_curve(y_test, proba[:, 1])
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.savefig('roc_curve.png')
    plt.close()
    
    # Print classification report
    report = classification_report(y_test, predictions)
    
    return report, cm, roc_auc

def predict_on_pcap(model, pcap_file):
    """Make predictions on new PCAP file"""
    # Prepare data in prediction mode
    data = prepare_data(pcap_file, prediction_mode=True)
    
    # Make predictions
    predictions = model.predict(data)
    probabilities = model.predict_proba(data)
    
    # Create results DataFrame
    results = pd.DataFrame({
        'Prediction': ['Normal' if p == 0 else 'Malicious' for p in predictions],
        'Confidence': np.max(probabilities, axis=1)
    })
    
    # Add source IP for reference
    original_data = NFStreamer(source=pcap_file).to_pandas()
    results['src_ip'] = original_data['src_ip']
    results['dst_ip'] = original_data['dst_ip']
    results['dst_port'] = original_data['dst_port']
    
    return results

def finetune_model(model, X_new, y_new, n_iterations=10):
    """Finetune existing model with new data"""
    print(f"Original model score on new data: {model.score(X_new, y_new)}")
    
    # Update parameters for fine-tuning
    model.set_params(warm_start=True)
    
    # Fine-tune the model
    for i in range(n_iterations):
        model.fit(X_new, y_new)
        print(f"Iteration {i+1}, score: {model.score(X_new, y_new)}")
    
    return model

def generate_report(results, output_file='report.txt'):
    """Generate a simple report with analysis results"""
    with open(output_file, 'w') as f:

        f.write("=== Network Traffic Analysis Report ===\n\n")
        f.write(f"Generated at: {pd.Timestamp.now()}\n\n")
        
        f.write("=== General Statistics ===\n")
        f.write(f"Total flows analyzed: {len(results)}\n")
        prediction_counts = results['Prediction'].value_counts()
        f.write(f"Normal flows: {prediction_counts.get('Normal', 0)}\n")
        f.write(f"Malicious flows: {prediction_counts.get('Malicious', 0)}\n\n")
        
        f.write("=== Malicious Flow Details ===\n")
        malicious_flows = results[results['Prediction'] == 'Malicious'].sort_values('Confidence', ascending=False)
        
        if len(malicious_flows) > 0:
            for idx, flow in malicious_flows.iterrows():
                f.write(f"\nFlow {idx + 1}:\n")
                f.write(f"Source IP: {flow['src_ip']}\n")
                f.write(f"Destination IP: {flow['dst_ip']}\n")
                f.write(f"Destination Port: {flow['dst_port']}\n")
                f.write(f"Confidence: {flow['Confidence']:.2f}\n")
        else:
            f.write("No malicious flows detected.\n\n")
        
        f.write("\n=== Summary ===\n")
        malicious_percentage = (len(malicious_flows) / len(results)) * 100 if len(results) > 0 else 0
        f.write(f"Percentage of malicious flows: {malicious_percentage:.2f}%\n")

def save_detailed_report(results, report_dir='reports'):
    """Save detailed report with visualizations"""
    
    os.makedirs(report_dir, exist_ok=True)
    timestamp = pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')
    
    report_file = os.path.join(report_dir, f'report_{timestamp}.txt')
    generate_report(results, report_file)
    
    plt.figure(figsize=(8, 6))
    results['Prediction'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Traffic Distribution')
    plt.savefig(os.path.join(report_dir, f'traffic_distribution_{timestamp}.png'))
    plt.close()
    
    plt.figure(figsize=(8, 6))
    sns.histplot(data=results, x='Confidence', hue='Prediction', bins=20)
    plt.title('Prediction Confidence Distribution')
    plt.savefig(os.path.join(report_dir, f'confidence_distribution_{timestamp}.png'))
    plt.close()

@click.group()
def cli():
    """Network Flow Classification Tool"""
    pass

@cli.command()
@click.argument('normal_pcap', type=click.Path(exists=True))
@click.argument('malicious_pcap', type=click.Path(exists=True))
@click.option('--model-output', default='flow_classifier.joblib', help='Path to save the trained model')
def train(normal_pcap, malicious_pcap, model_output):
    """Train a new model using normal and malicious PCAP files"""
    # Prepare data
    print("Preparing data...")
    data = prepare_data(normal_pcap, malicious_pcap)
    
    # Split data
    X = data.drop('label', axis=1)
    y = data['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print("Training model...")
    model, best_params = train_model(X_train, y_train)
    print("\nBest parameters:", best_params)
    
    # Evaluate model
    print("\nEvaluating model...")
    report, cm, roc_auc = evaluate_model(model, X_test, y_test)
    print("\nClassification Report:")
    print(report)
    
    # Save model
    joblib.dump(model, model_output)
    print(f"\nModel saved to: {model_output}")
    print("Confusion matrix and ROC curve plots have been saved.")

@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.argument('model_path', type=click.Path(exists=True))
@click.option('--report-dir', default='reports', help='Directory for saving reports')
def predict(pcap_file, model_path, report_dir):
    """Predict on new PCAP file using trained model"""
    try:
        # Load model
        print(f"Loading model from {model_path}...")
        model = joblib.load(model_path)
        
        # Make predictions
        print(f"Analyzing {pcap_file}...")
        results = predict_on_pcap(model, pcap_file)
        print("\nPrediction Results:")
        print(results['Prediction'].value_counts())
        
        # Generate and save report
        print(f"\nGenerating report in {report_dir}...")
        save_detailed_report(results, report_dir)
        print("Report generation completed.")
            
    except Exception as e:
        print(f"Error during prediction: {str(e)}")

@cli.command()
@click.argument('normal_pcap', type=click.Path(exists=True))
@click.argument('malicious_pcap', type=click.Path(exists=True))
@click.argument('model_path', type=click.Path(exists=True))
@click.option('--iterations', default=10, help='Number of fine-tuning iterations')
def finetune(normal_pcap, malicious_pcap, model_path, iterations):
    """Finetune existing model with new data"""
    try:
        # Load existing model
        print(f"Loading existing model from {model_path}...")
        model = joblib.load(model_path)
        
        # Prepare new data
        print("Preparing new training data...")
        data = prepare_data(normal_pcap, malicious_pcap)
        X = data.drop('label', axis=1)
        y = data['label']
        
        # Finetune
        print("Fine-tuning model...")
        updated_model = finetune_model(model, X, y, iterations)
        
        # Save updated model (nadpisanie istniejącego)
        joblib.dump(updated_model, model_path)
        print(f"\nModel updated and saved to: {model_path}")
        
    except Exception as e:
        print(f"Error during fine-tuning: {str(e)}")

def finetune_model(model, X_new, y_new, n_iterations=10):
    """Finetune existing model with new data"""
    # Save original number of estimators
    n_estimators_original = model.n_estimators
    print(f"Original model score on new data: {model.score(X_new, y_new)}")
    
    # compute class weights
    from sklearn.utils.class_weight import compute_class_weight
    classes = np.unique(y_new)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_new)
    class_weight_dict = dict(zip(classes, class_weights))
    
    # update parameters for fine-tuning
    model.set_params(
        warm_start=True,
        class_weight=class_weight_dict,
        n_estimators=n_estimators_original + 10 
    )
    
    # fine-tune the model
    scores = []
    for i in range(n_iterations):
        model.fit(X_new, y_new)
        current_score = model.score(X_new, y_new)
        scores.append(current_score)
        print(f"Iteration {i+1}, score: {current_score:.4f}")
        
        model.set_params(n_estimators=model.n_estimators + 10)
    
    best_score = max(scores)
    print(f"\nBest score achieved: {best_score:.4f}")
    
    return model

def main():
    cli()

if __name__ == '__main__':
    main()