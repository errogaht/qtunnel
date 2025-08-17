#!/bin/bash
# QTunnel Deployment Script for Q9x.ru VPS
# Usage: ./deploy-to-q9x.sh [version]
# Example: ./deploy-to-q9x.sh v1.1.0

set -e  # Exit on any error

echo "🚀 Deploying QTunnel to Q9x.ru VPS..."

# Get new version from argument or default to v1.1.0
NEW_VERSION=${1:-"v1.1.0"}
echo "📦 Deploying version: $NEW_VERSION"

# Validate version format
if [[ ! $NEW_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ Error: Invalid version format. Use format vX.Y.Z (e.g., v1.1.0)"
    exit 1
fi

# Navigate to Q9x.ru project
Q9X_DIR="/home/errogaht/aiprojects/q9x.ru"
QTUNNEL_VARS_FILE="$Q9X_DIR/modules/services/qtunnel/terraform/variables.tf"

if [ ! -d "$Q9X_DIR" ]; then
    echo "❌ Error: Q9x.ru project directory not found at $Q9X_DIR"
    exit 1
fi

cd "$Q9X_DIR"
echo "📁 Working directory: $(pwd)"

# Backup current variables file
cp "$QTUNNEL_VARS_FILE" "$QTUNNEL_VARS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
echo "💾 Backup created: $QTUNNEL_VARS_FILE.backup.$(date +%Y%m%d_%H%M%S)"

# Update version in variables file
echo "🔧 Updating QTunnel version to $NEW_VERSION..."
sed -i "s/default     = \"v[0-9]\+\.[0-9]\+\.[0-9]\+\"/default     = \"$NEW_VERSION\"/" "$QTUNNEL_VARS_FILE"

# Increment force rebuild counter
CURRENT_REBUILD=$(grep 'default     = "[0-9]*"' "$QTUNNEL_VARS_FILE" | tail -1 | grep -o '[0-9]*')
NEW_REBUILD=$((CURRENT_REBUILD + 1))
sed -i "s/default     = \"$CURRENT_REBUILD\"/default     = \"$NEW_REBUILD\"/" "$QTUNNEL_VARS_FILE"

echo "🔢 Force rebuild counter updated: $CURRENT_REBUILD -> $NEW_REBUILD"

# Show what changed
echo "📝 Changes made to $QTUNNEL_VARS_FILE:"
echo "   - QTunnel version: $NEW_VERSION"
echo "   - Force rebuild: $NEW_REBUILD"

# Confirm deployment
echo ""
read -p "🤔 Proceed with deployment? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Deployment cancelled"
    # Restore backup
    mv "$QTUNNEL_VARS_FILE.backup.$(date +%Y%m%d_%H%M%S)" "$QTUNNEL_VARS_FILE"
    exit 1
fi

echo "🔍 Checking deployment plan..."
terraform plan -target=module.services.module.qtunnel

echo ""
read -p "🚢 Apply changes to VPS? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Deployment cancelled"
    exit 1
fi

echo "🚢 Deploying to VPS..."
terraform apply -target=module.services.module.qtunnel --auto-approve

echo ""
echo "✅ Deployment completed successfully!"
echo "🌐 QTunnel is now available at: wss://qtunnel.q9x.ru/ws"
echo "📦 Version deployed: $NEW_VERSION"
echo ""
echo "🔗 Test the deployment:"
echo "   ./qtunnel --server wss://qtunnel.q9x.ru/ws --token 2af954f4f25ed532755c390d41b8f91828f9ea8648d2b0e47fb2deced96b23a4 3000"
echo ""
echo "📊 Check server status:"
echo "   curl https://qtunnel.q9x.ru/health"
echo ""
echo "📋 View logs:"
echo "   ssh -i /home/errogaht/.ssh/q9x_ru ubuntu@121.127.37.176 'docker logs qtunnel-server'"