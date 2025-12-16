# Lab Assignment 4 – CYBER-DEF25 Malware Detection Submission

## 1. Application overview
- The container bundles `model.pkl`, `inference.py`, and all dependencies defined in `requirements.txt` to meet the CYBER-DEF25 inference contract (logs in `/input/logs`, alerts out to `/output/alerts.csv`).
- `inference.py` loads the pickled logistic-regression pipeline, normalises the synthetic telemetry, classifies every log row and writes a time-stamped alert table that includes `threat_score` plus the sanitized telemetric fields.
- A short training helper (`scripts/train_model.py`) builds toy traffic data, trains the pipeline, and writes `model.pkl` so the container is self-sufficient.

## 2. Micro steps and evidence (replace placeholders with your screenshots)
1. **Environment prep** – install dependencies locally via `pip install -r requirements.txt` (see `requirements.txt`).
2. **Train the model** – run `& "C:/.../.venv/Scripts/python.exe" scripts/train_model.py` to generate `model.pkl`.
3. **Build the container** – `docker build -t collage-erp:latest .` and tag it `docker tag collage-erp:latest docker.io/mohamedahsan00/collage-erp:latest`.
4. **Push to Docker Hub** – `docker push docker.io/mohamedahsan00/collage-erp:latest`.
5. **Prepare Kubernetes storage** – apply the PVC manifest to allocate `malware-logs-pvc`.
6. **Deploy the workload** – apply the deployment and service YAMLs (see sections below).
7. **Validation ideas** – mount a host directory with CSV logs to `/input/logs`, run the pod, and inspect `/output/alerts.csv` for alerts.

*(Insert screenshots for steps 2–5 in the final report submission.)*

## 3. Containerisation details
- Image name: `collage-erp` (per environment block).
- Docker Hub reference: `docker.io/mohamedahsan00/collage-erp:latest`.
- Commands:
  1. `docker build -t collage-erp:latest .`
  2. `docker tag collage-erp:latest docker.io/mohamedahsan00/collage-erp:latest`
  3. `docker push docker.io/mohamedahsan00/collage-erp:latest`

## 4. Kubernetes manifests
Persistent storage, deployment, and service definitions are embedded below for reference and submission.

### PersistentVolumeClaim (PVC)
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: malware-logs-pvc
  labels:
    app: malware-detector
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
```

### Deployment manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: malware-detector
  labels:
    app: malware-detector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: malware-detector
  template:
    metadata:
      labels:
        app: malware-detector
    spec:
      initContainers:
        - name: prepare-storage
          image: busybox:1.36
          command:
            - sh
            - -c
            - mkdir -p /workspace/logs /workspace/output && chmod 755 /workspace
          volumeMounts:
            - name: logs-storage
              mountPath: /workspace
      containers:
        - name: inference
          image: docker.io/mohamedahsan00/collage-erp:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: logs-storage
              mountPath: /input/logs
              subPath: logs
            - name: logs-storage
              mountPath: /output
              subPath: output
      volumes:
        - name: logs-storage
          persistentVolumeClaim:
            claimName: malware-logs-pvc
```

### Service manifest
```yaml
apiVersion: v1
kind: Service
metadata:
  name: malware-detector
  labels:
    app: malware-detector
spec:
  type: ClusterIP
  selector:
    app: malware-detector
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

## 5. Notes and next actions
- Feed the `/input/logs` volume with CSVs that include `packet_rate`, `anomaly_score`, and optional `urgent_flag` for richer detection context.
- Collect `/output/alerts.csv` for post-processing or security dashboards.
- Add health probes or a lightweight REST wrapper if a service needs to expose a reachable API surface in the future.
