# Lab 0: Environment Setup

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 0 - Environment Setup |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to prepare and verify a local cloud-security laboratory environment before starting the later labs. The setup uses Docker to run containers and LocalStack, AWS CLI to communicate with LocalStack, kind to create a Kubernetes cluster inside Docker, and kubectl to manage the cluster. OpenSSL and oathtool are also checked because they are required for encryption, certificates, and MFA/TOTP activities in later labs.

All services are run locally. Therefore, the environment can be tested without using a real AWS account or creating cloud resources. The final verification confirms that Docker is working, LocalStack is healthy, AWS CLI can reach the LocalStack endpoint, and the Kubernetes control plane is ready.

## Environment and Tools

The cheatsheet recommends using Git Bash or WSL on Windows because several lab commands use Bash syntax. The screenshots show that the commands were executed in an Ubuntu terminal running in VirtualBox.

| Tool | Purpose |
|---|---|
| Docker | Runs containers and LocalStack |
| AWS CLI v2 | Sends AWS commands to LocalStack |
| kind | Creates Kubernetes in Docker |
| kubectl | Controls the Kubernetes cluster |
| OpenSSL | Provides encryption and certificate tools |
| oathtool | Generates MFA/TOTP codes |
| LocalStack | Simulates AWS services locally |

## Step 1: Verify Docker

Docker must be installed and running before LocalStack or kind can be used. The Docker version was checked first:

```bash
docker --version
```

The environment returned Docker version `29.6.2`. A test container was then started using the official Hello World image:

```bash
docker run --rm hello-world
```

The output displayed **“Hello from Docker!”** and stated that the installation was working correctly. The `--rm` option automatically removes the test container after it finishes.

<img width="724" height="124" alt="1-dockerversion" src="https://github.com/user-attachments/assets/8c8f3fec-87e2-428b-acff-eb5382224844" />

## Step 2: Verify kind and kubectl

kind runs Kubernetes nodes as Docker containers, while kubectl is the command-line client used to control Kubernetes. Their versions were checked with:

```bash
kind version
kubectl version --client
```

The installed versions shown in the evidence are:

- kind `v0.23.0`
- kubectl client `v1.36.3`
- Kustomize `v5.8.1`

<img width="556" height="90" alt="2-kindkubectlversion" src="https://github.com/user-attachments/assets/da2126e8-8afc-47bb-9013-1c29980f6a1b" />

## Step 3: Verify OpenSSL and oathtool

The helper tools were verified for use in future labs:

```bash
openssl version
oathtool --version
```

The terminal output shows OpenSSL `3.0.2` and oathtool `2.6.7`. OpenSSL will support cryptographic tasks, while oathtool can generate one-time MFA/TOTP codes.

<img width="720" height="179" alt="3-openssloathtoolversion" src="https://github.com/user-attachments/assets/19aa4da9-b283-43dc-b4fb-65015eabd39c" />

## Step 4: Start and Check LocalStack

LocalStack provides a local simulation of AWS services. It was started in a detached Docker container and mapped to port 4566:

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:4.4.0
```

The LocalStack health endpoint was checked with:

```bash
curl http://localhost:4566/_localstack/health
```

The response reported that services including CloudFormation, DynamoDB, EC2, IAM, Lambda, S3, Secrets Manager, and STS were available. This confirms that LocalStack started successfully and can accept local AWS API requests.

<img width="858" height="262" alt="4-dockerrunhealth" src="https://github.com/user-attachments/assets/967c400a-9343-4c47-960b-b49a9a356d4d" />

The LocalStack health endpoint was also opened in a web browser at `http://localhost:4566/_localstack/health`. The JSON response displayed the available LocalStack services, providing an additional visual confirmation that the local AWS simulator was healthy.

<img width="1211" height="773" alt="4 1-verifyhealth" src="https://github.com/user-attachments/assets/6bcfa089-cd7b-4b78-b4fc-971759389413" />

## Step 5: Configure AWS CLI for LocalStack

LocalStack does not require real AWS credentials. Dummy values were configured so that the AWS CLI would not prompt for credentials:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

An endpoint variable was then created for the current terminal session:

```bash
EP='--endpoint-url=http://localhost:4566'
```

The following command verified that the AWS CLI was communicating with LocalStack rather than the real AWS cloud:

```bash
aws $EP sts get-caller-identity
```

The returned identity used the LocalStack example account `000000000000` and a root ARN. This demonstrates successful AWS CLI connectivity to the local simulator.

<img width="738" height="181" alt="5-awsconfigure" src="https://github.com/user-attachments/assets/3ddfbe33-a80e-4f20-835d-4ce6ca331bb2" />

## Step 6: Create the Kubernetes Cluster

A kind cluster was created with the name `lab0`:

```bash
kind create cluster --name lab0
```

The output confirmed that kind ensured the node image, prepared the nodes, wrote the configuration, started the control plane, installed CNI networking, and installed StorageClass support. The kubectl context was set to `kind-lab0`.

<img width="660" height="223" alt="6-createcluster" src="https://github.com/user-attachments/assets/cdd670a0-b056-4b2f-8d20-02e650c71689" />

## Step 7: Verify Kubernetes Cluster Information

The cluster control plane and node status were checked using:

```bash
kubectl cluster-info --context kind-lab0
kubectl get nodes
```

The control plane was reported as running at `https://127.0.0.1:40707`. The node list showed `lab0-control-plane` with status **Ready**, role `control-plane`, and Kubernetes version `v1.30.0`. This confirms that the local Kubernetes cluster is operational.

<img width="861" height="164" alt="7-clusterinfo" src="https://github.com/user-attachments/assets/4e64bd2c-2f95-4f27-b20e-713fae027dc8" />

## Verification Summary

| Check | Result |
|---|---|
| Docker version and Hello World container | Passed |
| kind and kubectl available | Passed |
| OpenSSL and oathtool available | Passed |
| LocalStack container started | Passed |
| LocalStack health endpoint available | Passed |
| AWS CLI configured with local endpoint | Passed |
| AWS STS caller identity returned | Passed |
| kind cluster `lab0` created | Passed |
| Kubernetes control plane running | Passed |
| Kubernetes node status Ready | Passed |

## Troubleshooting Reference

| Symptom | Fix |
|---------|-----|
| "Cannot connect to the Docker daemon" | Docker Desktop is not running — start it |
| Docker won't start / very slow | Enable virtualization in BIOS; enable WSL 2 + Virtual Machine Platform |
| Port 4566 already in use | `docker rm -f localstack`, then start again |
| aws: "Could not connect to the endpoint URL" | LocalStack is not running, or forgot `--endpoint-url` / `$EP` |
| "aws: command not found" / "kubectl not found" | Tool not on PATH — re-run install; open a new terminal |
| heredoc / sha256sum errors on Windows | You are in PowerShell/CMD — switch to Git Bash or WSL |
| `kind create cluster` fails | Docker not running, or low memory — ensure Docker has ≥ 4 GB |
| Image download is slow in the lab | Pre-pull images before class on Wi-Fi |

## Useful Start and Stop Commands

To start the existing LocalStack container in a later session:

```bash
docker start localstack
```

To inspect the Kubernetes cluster:

```bash
docker ps
kind get clusters
kubectl get nodes
```

When the environment is no longer needed, the lab resources can be stopped or removed:

```bash
docker stop localstack
kind delete cluster --name lab0
```

## Conclusion

The Lab 0 environment was successfully prepared. Docker is functioning, LocalStack is healthy on port 4566, and AWS CLI commands can be directed to the local AWS simulator using the `EP` endpoint variable. The kind cluster `lab0` was also created successfully, and its control-plane node is Ready. The environment is therefore ready for the subsequent cloud computing security labs.


## References
- Docker Documentation: https://docs.docker.com/
- AWS CLI Documentation: https://docs.aws.amazon.com/cli/
- Kind Documentation: https://kind.sigs.k8s.io/
- Kubernetes kubectl Documentation: https://kubernetes.io/docs/reference/kubectl/
- LocalStack Documentation: https://docs.localstack.cloud/
- OpenSSL Documentation: https://www.openssl.org/docs/
- OATH Toolkit Documentation: https://www.nongnu.org/oath-toolkit/
