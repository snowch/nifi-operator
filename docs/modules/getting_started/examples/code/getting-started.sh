#!/usr/bin/env bash
set -euo pipefail

# The getting started guide script
# It uses tagged regions which are included in the documentation
# https://docs.asciidoctor.org/asciidoc/latest/directives/include-tagged-regions/
#
# There are two variants to go through the guide - using stackablectl or helm
# The script takes either 'stackablectl' or 'helm' as an argument
#
# The script can be run as a test as well, to make sure that the tutorial works
# It includes some assertions throughout, and at the end especially.

if [ $# -eq 0 ]
then
  echo "Installation method argument ('helm' or 'stackablectl') required."
  exit 1
fi

case "$1" in
"helm")
echo "Adding 'stackable-stable' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable-stable https://repo.stackable.tech/repository/helm-stable/
# end::helm-add-repo[]
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator stackable-stable/commons-operator --version 0.4.0
helm install --wait secret-operator stackable-stable/secret-operator --version 0.6.0
helm install --wait zookeeper-operator stackable-stable/zookeeper-operator --version 0.12.0
helm install --wait nifi-operator stackable-stable/nifi-operator --version 0.8.0
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=0.4.0 \
  secret=0.6.0 \
  zookeeper=0.12.0 \
  nifi=0.8.0
# end::stackablectl-install-operators[]
;;
*)
echo "Need to provide 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Installing ZooKeeper"
# tag::install-zookeeper[]
kubectl apply -f - <<EOF
---
apiVersion: zookeeper.stackable.tech/v1alpha1
kind: ZookeeperCluster
metadata:
  name: simple-zk
spec:
  version: 3.8.0-stackable0.7.1
  servers:
    roleGroups:
      default:
        replicas: 3
EOF
# end::install-zookeeper[]

echo "Create a ZNode"
# tag::install-znode[]
kubectl apply -f - <<EOF
---
apiVersion: zookeeper.stackable.tech/v1alpha1
kind: ZookeeperZnode
metadata:
  name: simple-nifi-znode
spec:
  clusterRef:
    name: simple-zk
EOF
# end::install-znode[]

sleep 5

echo "Awaiting ZooKeeper rollout finish"
# tag::watch-zookeeper-rollout[]
kubectl rollout status --watch statefulset/simple-zk-server-default
# end::watch-zookeeper-rollout[]

echo "Create NiFi admin credentials"
# tag::install-nifi-credentials[]
kubectl apply -f - <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: nifi-admin-credentials-simple
stringData:
  username: admin
  password: admin
EOF
# end::install-nifi-credentials[]

echo "Create a NiFi instance"
# tag::install-nifi[]
kubectl apply -f - <<EOF
---
apiVersion: nifi.stackable.tech/v1alpha1
kind: NifiCluster
metadata:
  name: simple-nifi
spec:
  version: 1.18.0-stackable0.1.0
  zookeeperConfigMapName: simple-nifi-znode
  config:
    authentication:
      method:
        singleUser:
          adminCredentialsSecret: nifi-admin-credentials-simple
          autoGenerate: true
    sensitiveProperties:
      keySecret: nifi-sensitive-property-key
      autoGenerate: true
  nodes:
    roleGroups:
      default:
        replicas: 2
EOF
# end::install-nifi[]

sleep 5

echo "Awaiting NiFi rollout finish"
# tag::wait-nifi-rollout[]
kubectl wait -l statefulset.kubernetes.io/pod-name=simple-nifi-node-default-0 \
--for=condition=ready pod --timeout=1200s && \
kubectl wait -l statefulset.kubernetes.io/pod-name=simple-nifi-node-default-1 \
--for=condition=ready pod --timeout=1200s
# end::wait-nifi-rollout[]

sleep 5

echo "Get a single node where a NiFi pod is running"
# tag::get-nifi-node-name[]
nifi_node_name=$(kubectl get endpoints simple-nifi --output=jsonpath='{.subsets[0].addresses[0].nodeName}') && \
echo "NodeName: $nifi_node_name"
# end::get-nifi-node-name[]

echo "List $nifi_node_name node internal ip"
# tag::get-nifi-node-ip[]
nifi_node_ip=$(kubectl get nodes -o jsonpath="{.items[?(@.metadata.name==\"$nifi_node_name\")].status.addresses[?(@.type==\"InternalIP\")].address}") && \
echo "NodeIp: $nifi_node_ip"
# end::get-nifi-node-ip[]

echo "Get node port from service"
# tag::get-nifi-service-port[]
nifi_service_port=$(kubectl get service -o jsonpath="{.items[?(@.metadata.name==\"simple-nifi\")].spec.ports[?(@.name==\"https\")].nodePort}") && \
echo "NodePort: $nifi_service_port"
# end::get-nifi-service-port[]

echo "Create NiFi url"
# tag::create_nifi_url[]
nifi_url="https://$nifi_node_ip:$nifi_service_port" && \
echo "NiFi web interface: $nifi_url"
# end::create_nifi_url[]

echo "Starting nifi tests"
chmod +x ./test-nifi.sh
./test-nifi.sh "$nifi_url"
