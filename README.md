# Trading Contacts — Deploy Runbook

End-to-end: schema in RDS → container in ECR → Deployment in K8s → Teleport application access.

## 0. Pick a strong password for the app user

The webapp connects to RDS as `trading_app` with a stored password (humans use Teleport's database protocol with `rds_iam`). Pick something:

```powershell
$DB_PWD = "<choose-a-strong-password>"
```

## 1. Schema + seed + app user (on RDS)

Edit `schema.sql` and replace `CHANGE_ME` with `$DB_PWD`. Then run via psql against the RDS master credentials:

```powershell
$env:PGPASSWORD = "<your-rds-master-password>"
psql "host=database-2.cluster-cilmq64861va.us-east-1.rds.amazonaws.com port=5432 dbname=postgres user=postgres sslmode=require" -f schema.sql
```

If you don't have psql locally, you can also paste the file contents into the Teleport web shell (broken-tooth has working access right now).

Verify:

```sql
SELECT count(*) FROM contacts;       -- should be 8
SELECT count(*) FROM call_log;       -- 0 initially
\du trading_app                       -- shows the role
```

## 2. Build the container image and push to ECR

```powershell
$AWS_ACCOUNT = "807291695385"
$REGION      = "us-east-1"
$REPO        = "trading-contacts"
$IMAGE       = "$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO`:v1"

# Create the ECR repo if it doesn't exist (idempotent)
aws ecr describe-repositories --repository-names $REPO --region $REGION 2>$null
if ($LASTEXITCODE -ne 0) {
  aws ecr create-repository --repository-name $REPO --region $REGION
}

# Authenticate Docker to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin "$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com"

# Build + push
docker build -t $IMAGE .
docker push $IMAGE

Write-Host "Pushed: $IMAGE"
```

## 3. Substitute and apply the K8s manifest

```powershell
(Get-Content k8s.yaml) `
  -replace 'IMAGE_PLACEHOLDER', $IMAGE `
  -replace 'DB_PASSWORD_PLACEHOLDER', $DB_PWD `
  | Set-Content k8s-rendered.yaml -Encoding utf8

kubectl apply -f k8s-rendered.yaml
kubectl rollout status deploy/trading-contacts -n trading
kubectl get pods -n trading -l app=trading-contacts
```

Smoke test inside the cluster:

```powershell
kubectl run curlbox --rm -it --image=curlimages/curl -n trading -- `
  sh -c "curl -s http://trading-contacts.trading.svc.cluster.local/api/contacts | head -c 500"
```

You should see JSON of the seeded contacts.

## 4. Register with Teleport application access

Edit `../agent-values.yaml` and add to the `apps:` block:

```yaml
  - name: contacts
    uri: http://trading-contacts.trading.svc.cluster.local:80
    labels:
      env: demo
      purpose: trading-app
      protocol: app
      compliance: mifid-ii
```

Apply:

```powershell
helm upgrade teleport-kube-agent teleport/teleport-kube-agent -n teleport-agent -f ..\agent-values.yaml --version 18.7.4
kubectl rollout status statefulset/teleport-kube-agent -n teleport-agent
```

## 5. Open it

In the Teleport web UI, refresh Resources. A new app `contacts` should appear. Click **Launch** → opens `https://contacts.patient-credit.trial.teleport.sh`. You should see the contact cards.

Click **Call <name>** on any contact — your OS launches the registered phone handler (Teams, FaceTime, etc.) with the dial URI. Each click hits `/api/contacts/:id/log-call` first, which writes a row in `call_log` tagged with your Teleport JWT identity.

Scroll to the **Recent calls** section — your call shows up within a few seconds.

## 6. Demo talking points

- *"Trader logs in via Teleport SSO once. Click Launch on contacts, the app proxies through Teleport's identity-aware gateway, JWT goes to the backend, and the backend stamps every call into a MiFID-II audit trail with the trader's identity."*
- *"For ad-hoc DBA access — say, to investigate a stuck row — power users `tsh db connect` directly to RDS via Teleport's database protocol. Different protocol, same identity, same audit log."*
- *"Tel: URI dispatches to the OS — works with Teams, FaceTime, Skype, hardware turret softclients. The webapp doesn't need to know which softphone the trader uses."*

## Troubleshooting

**Pod CrashLoopBackOff** → `kubectl logs deploy/trading-contacts -n trading`. Most likely DB connection — verify `DB_HOST`, `DB_PASSWORD`, network reachability from the pod to RDS (the same VPC, security group should already allow it since the cluster is in vpc-088a50155f78ba8de).

**Frontend loads but shows "No contacts"** → schema didn't seed; rerun `schema.sql`.

**Call button doesn't open Teams** → set Teams as your default phone handler in Windows Settings → Apps → Default apps → Tel.

**JWT identity shows "anonymous"** → you're hitting the app directly (e.g. via port-forward) bypassing Teleport. Open it via the Launch button.
