#!/usr/bin/env bash
#
# Download minotari proto files
#

# pre
# tariNetwork="heads/development"; bash ./get-protos.sh

# rc
# tariNetwork="heads/nextnet"; bash ./get-protos.sh

#tariNetwork="heads/nextnet"
#tariNetwork="tags/v2.0.1"

tariNetwork=${tariNetwork:-"heads/development"}

# Proto list
tari_proto_list=(
  base_node.proto
  sidechain_types.proto
  block.proto
  transaction.proto
  network.proto
  types.proto
)

# https://raw.githubusercontent.com/tari-project/tari/refs/heads/development/applications/minotari_app_grpc/proto/base_node.proto
#tariNetwork=development

# https://raw.githubusercontent.com/tari-project/tari/refs/heads/nextnet/applications/minotari_app_grpc/proto/block.proto
# https://raw.githubusercontent.com/tari-project/tari/refs/tags/v2.0.1/applications/minotari_app_grpc/proto/base_node.proto
#tariNetwork=${tariNetwork:-nextnet}
#tariNetwork="heads/nextnet"
#tariNetwork="tags/v2.0.1"

baseURL=https://raw.githubusercontent.com/tari-project/tari/refs/${tariNetwork}/applications/minotari_app_grpc/proto

for ProtoVar in "${tari_proto_list[@]}"; do
  echo "Downloading ${ProtoVar}"
  wget -v "${baseURL}/${ProtoVar}"
done
