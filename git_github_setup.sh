#!/bin/bash
# Complete Git and GitHub setup for MkDocs documentation

set -e

echo "🚀 Setting up Git and GitHub for CVE Research Documentation"
echo "=========================================================="
echo "Repository: https://github.com/EID-ALBEDAH/research-doc.git"
echo "Working Directory: /opt/cve-research-docs"
echo ""

# Check if we're in the right directory
if [ ! -d "/opt/cve-research-docs" ]; then
    echo "❌ Directory /opt/cve-research-docs not found"
    exit 1
fi

cd /opt/cve-research-docs

# Step 1: Install Git if not installed
echo "📦 Step 1: Ensuring Git is installed..."
if ! command -v git &> /dev/null; then
    apt update
    apt install -y git
    echo "✅ Git installed"
else
    echo "✅ Git is already installed"
    git --version
fi

# Step 2: Configure Git (update with your details)
echo ""
echo "📝 Step 2: Configuring Git..."
echo "Enter your details for Git configuration:"

read -p "Git username (EID-ALBEDAH): " GIT_USERNAME
GIT_USERNAME=${GIT_USERNAME:-"EID-ALBEDAH"}

read -p "Git email: " GIT_EMAIL

git config --global user.name "$GIT_USERNAME"
git config --global user.email "$GIT_EMAIL"
git config --global init.defaultBranch main

echo "✅ Git configured:"
echo "   Username: $(git config --global user.name)"
echo "   Email: $(git config --global user.email)"

# Step 3: Choose authentication method
echo ""
echo "🔐 Step 3: Choose GitHub Authentication Method"
echo "=============================================="
echo "1. HTTPS with Personal Access Token (Recommended - Easier)"
echo "2. SSH with Key Pair (More secure for automated deployments)"
echo ""
read -p "Choose method (1 or 2): " AUTH_METHOD

if [ "$AUTH_METHOD" = "1" ]; then
    echo ""
    echo "🔑 HTTPS with Personal Access Token Selected"
    echo "==========================================="
    echo "You'll need to create a Personal Access Token on GitHub:"
    echo "1. Go to: https://github.com/settings/tokens"
    echo "2. Click 'Generate new token (classic)'"
    echo "3. Set expiration: No expiration (or your preference)"
    echo "4. Select scopes: repo, workflow, write:packages"
    echo "5. Copy the token - you'll need it when pushing"
    echo ""
    REPO_URL="https://github.com/EID-ALBEDAH/research-doc.git"
    
elif [ "$AUTH_METHOD" = "2" ]; then
    echo ""
    echo "🔑 SSH Key Authentication Selected"
    echo "================================="
    
    # Check if SSH key exists
    if [ ! -f "/root/.ssh/id_rsa" ]; then
        echo "Generating SSH key..."
        ssh-keygen -t rsa -b 4096 -C "$GIT_EMAIL" -f /root/.ssh/id_rsa -N ""
        echo "✅ SSH key generated"
    else
        echo "✅ SSH key already exists"
    fi
    
    echo ""
    echo "📋 Add this SSH key to your GitHub account:"
    echo "1. Go to: https://github.com/settings/ssh"
    echo "2. Click 'New SSH key'"
    echo "3. Copy and paste this public key:"
    echo ""
    echo "--- START SSH KEY ---"
    cat /root/.ssh/id_rsa.pub
    echo "--- END SSH KEY ---"
    echo ""
    read -p "Press Enter after adding the SSH key to GitHub..."
    
    REPO_URL="git@github.com:EID-ALBEDAH/research-doc.git"
else
    echo "❌ Invalid choice"
    exit 1
fi

# Step 4: Initialize Git repository
echo ""
echo "📁 Step 4: Initializing Git Repository"
echo "======================================"

# Check if already a git repo
if [ -d ".git" ]; then
    echo "✅ Git repository already exists"
    echo "Current remote:"
    git remote -v 2>/dev/null || echo "No remotes configured"
else
    echo "Initializing new Git repository..."
    git init
    echo "✅ Git repository initialized"
fi

# Step 5: Add GitHub remote
echo ""
echo "🌐 Step 5: Adding GitHub Remote"
echo "==============================="

# Remove existing origin if it exists
git remote remove origin 2>/dev/null || true

# Add new origin
git remote add origin "$REPO_URL"
echo "✅ Added remote origin: $REPO_URL"

# Step 6: Create .gitignore file
echo ""
echo "📝 Step 6: Creating .gitignore"
echo "=============================="

cat > .gitignore << 'EOF'
# MkDocs
site/
.cache/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
mkdocs-env/
.env

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Editors
.vscode/
.idea/
*.swp
*.swo
*~

# Logs
*.log
logs/

# Temporary files
*.tmp
*.temp

# Jupyter
.ipynb_checkpoints/
*/.ipynb_checkpoints/*

# Node modules (if any)
node_modules/

# Build outputs
dist/
build/
EOF

echo "✅ Created .gitignore"

# Step 7: Create README.md
echo ""
echo "📝 Step 7: Creating README.md"
echo "============================="

cat > README.md << 'EOF'
# CVE Lifecycle Analysis Research Hub

> Analyzing CVE Lifecycle and Relationships with Exploits, Patches, CWEs, and CPEs

## Overview

This repository contains the documentation and research materials for CVE (Common Vulnerabilities and Exposures) lifecycle analysis. The project explores the relationships between vulnerabilities, exploits, patches, and security frameworks.

## Features

- 📊 **Comprehensive Analysis**: CVE lifecycle patterns and temporal dynamics
- 🔍 **Multi-Vendor Research**: Comparative analysis across different vendors
- 🤖 **Machine Learning**: Exploit prediction and patch prioritization models
- 📚 **Interactive Documentation**: Built with MkDocs Material
- 🔬 **Jupyter Notebooks**: Interactive analysis and visualization

## Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/EID-ALBEDAH/research-doc.git
cd research-doc

# Create virtual environment
python -m venv mkdocs-env
source mkdocs-env/bin/activate  # Linux/Mac
# mkdocs-env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Serve documentation locally
mkdocs serve
```

### Documentation Structure

```
docs/
├── index.md                    # Home page
├── about.md                    # About the research
├── data/                       # Data and schema documentation
├── analysis/                   # Analysis and visualizations
├── research/                   # Research ideas and exploration
├── publications/               # Conference papers
├── methodology/                # Research methodology
├── future/                     # Future work
└── resources/                  # References and tools
```

## Research Areas

- **Exploit Prediction**: Machine learning models to predict CVE exploitation
- **Patch Prioritization**: Risk assessment and priority modeling
- **Lifecycle Modeling**: Heavy-tailed analysis and survival models
- **Vendor Comparison**: Commercial vs open source response analysis

## Technologies Used

- **Documentation**: MkDocs with Material theme
- **Analysis**: Python, Pandas, NumPy, Scikit-learn
- **Visualization**: Matplotlib, Seaborn, Plotly
- **Notebooks**: Jupyter Lab
- **Deployment**: GitHub Actions, Docker

## Contributing

This is an academic research project. For questions or collaboration opportunities, please contact the author.

## Author

**Eid ALBADDAH**  
CVE Lifecycle Analysis Researcher

## License

This project is for academic research purposes.
EOF

echo "✅ Created README.md"

# Step 8: Create requirements.txt
echo ""
echo "📝 Step 8: Creating requirements.txt"
echo "===================================="

cat > requirements.txt << 'EOF'
# MkDocs and theme
mkdocs>=1.5.0
mkdocs-material>=9.4.0
mkdocs-jupyter>=0.24.0

# Additional MkDocs plugins
mkdocs-minify-plugin>=0.7.0
mkdocs-macros-plugin>=1.0.0

# Data analysis
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.15.0

# Machine learning
scikit-learn>=1.3.0
scipy>=1.11.0

# Jupyter
jupyterlab>=4.0.0
notebook>=7.0.0
ipywidgets>=8.0.0

# Development tools
black>=23.0.0
pytest>=7.4.0
EOF

echo "✅ Created requirements.txt"

# Step 9: Add all files to git
echo ""
echo "📁 Step 9: Adding Files to Git"
echo "=============================="

echo "Adding files to git..."
git add .
echo "✅ Files staged"

echo ""
echo "Files to be committed:"
git status --porcelain | head -20
if [ $(git status --porcelain | wc -l) -gt 20 ]; then
    echo "... and $(( $(git status --porcelain | wc -l) - 20 )) more files"
fi

# Step 10: Initial commit
echo ""
echo "📝 Step 10: Creating Initial Commit"
echo "==================================="

git commit -m "Initial commit: CVE Research Documentation

- Add MkDocs configuration and documentation structure
- Include research analysis and methodology
- Set up Jupyter notebooks for interactive analysis
- Configure publication and future work sections
- Add comprehensive .gitignore and requirements.txt"

echo "✅ Initial commit created"

# Step 11: Push to GitHub
echo ""
echo "🚀 Step 11: Pushing to GitHub"
echo "============================="

echo "Pushing to GitHub..."
if [ "$AUTH_METHOD" = "1" ]; then
    echo ""
    echo "🔑 You'll be prompted for your GitHub credentials:"
    echo "Username: Your GitHub username"
    echo "Password: Your Personal Access Token (NOT your GitHub password)"
    echo ""
fi

# Push to GitHub
if git push -u origin main; then
    echo "✅ Successfully pushed to GitHub!"
else
    echo "❌ Push failed. Common issues:"
    echo "- Personal Access Token might be incorrect"
    echo "- SSH key might not be added to GitHub"
    echo "- Repository might not exist or be accessible"
    echo ""
    echo "You can try pushing again with:"
    echo "git push -u origin main"
fi

# Step 12: Show final status
echo ""
echo "✅ Git Setup Complete!"
echo "======================"
echo ""
echo "📋 Repository Information:"
echo "GitHub URL: https://github.com/EID-ALBEDAH/research-doc"
echo "Clone URL: $REPO_URL"
echo "Branch: main"
echo ""
echo "🔧 Current Git Status:"
git status

echo ""
echo "📊 Repository Stats:"
echo "Files tracked: $(git ls-files | wc -l)"
echo "Total commits: $(git rev-list --count HEAD)"

echo ""
echo "🔗 Useful Git Commands:"
echo "git status              # Check repository status"
echo "git add .               # Stage all changes"
echo "git commit -m 'message' # Commit changes"
echo "git push                # Push to GitHub"
echo "git pull                # Pull from GitHub"

echo ""
echo "🎯 Next Steps:"
echo "1. Visit: https://github.com/EID-ALBEDAH/research-doc"
echo "2. Verify your files are uploaded"
echo "3. Set up GitHub Actions for automated deployment"
echo ""
echo "💡 For GitHub Actions setup, run the next script!"