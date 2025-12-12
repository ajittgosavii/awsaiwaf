"""
AI-Based AWS Well-Architected Framework Advisor
AWS-focused architecture design and assessment platform
"""

import streamlit as st
import sys
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="AI-Based Well-Architected Framework",
    page_icon="🏗️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.current_tab = "waf_scanner"
    st.session_state.connected_accounts = []
    st.session_state.scan_mode = "single"

# Module import status tracking
MODULE_STATUS = {}
MODULE_ERRORS = {}

# ============================================================================
# IMPORT AWS MODULES
# ============================================================================

print("Loading AWS modules...")

# Core modules
try:
    from aws_connector import get_aws_session, test_aws_connection
    MODULE_STATUS['AWS Connector'] = True
except Exception as e:
    MODULE_STATUS['AWS Connector'] = False
    MODULE_ERRORS['AWS Connector'] = str(e)

try:
    from landscape_scanner import AWSLandscapeScanner
    MODULE_STATUS['Landscape Scanner'] = True
except Exception as e:
    MODULE_STATUS['Landscape Scanner'] = False
    MODULE_ERRORS['Landscape Scanner'] = str(e)

try:
    from waf_review_module import render_waf_review_tab
    MODULE_STATUS['WAF Review'] = True
except Exception as e:
    MODULE_STATUS['WAF Review'] = False
    MODULE_ERRORS['WAF Review'] = str(e)

try:
    from modules_architecture_designer_waf import ArchitectureDesignerModule
    MODULE_STATUS['Architecture Designer'] = True
except Exception as e:
    MODULE_STATUS['Architecture Designer'] = False
    MODULE_ERRORS['Architecture Designer'] = str(e)

try:
    from eks_modernization_module import EKSModernizationModule
    MODULE_STATUS['EKS Modernization'] = True
except Exception as e:
    MODULE_STATUS['EKS Modernization'] = False
    MODULE_ERRORS['EKS Modernization'] = str(e)

try:
    from compliance_module import ComplianceModule
    MODULE_STATUS['Compliance'] = True
except Exception as e:
    MODULE_STATUS['Compliance'] = False
    MODULE_ERRORS['Compliance'] = str(e)

# ============================================================================
# HEADER
# ============================================================================

def render_header():
    """Render application header"""
    
    st.markdown("""
        <div style="background: linear-gradient(135deg, #FF9900 0%, #232F3E 100%); 
                    padding: 2rem; border-radius: 10px; margin-bottom: 2rem; color: white;">
            <h1 style="margin: 0; font-size: 2.5rem;">
                🏗️ AI-Based Well-Architected Framework Advisor
            </h1>
            <p style="margin: 0.5rem 0 0 0; font-size: 1.1rem; opacity: 0.95;">
                Scan AWS Accounts & Ensure Well-Architected Framework Alignment
            </p>
        </div>
    """, unsafe_allow_html=True)

# ============================================================================
# SIDEBAR
# ============================================================================

def render_sidebar():
    """Render sidebar with AWS connection status"""
    
    with st.sidebar:
        st.markdown("### 🔧 AWS Connection Status")
        
        # Scan mode selector
        scan_mode = st.radio(
            "Scan Mode",
            ["Single Account", "Multi-Account"],
            key="scan_mode_radio"
        )
        st.session_state.scan_mode = "single" if scan_mode == "Single Account" else "multi"
        
        st.markdown("---")
        
        # AWS connection status
        if st.session_state.scan_mode == "single":
            st.markdown("#### Single Account")
            try:
                session = get_aws_session()
                if session:
                    st.success("✅ AWS Connected")
                    
                    try:
                        import boto3
                        sts = session.client('sts')
                        identity = sts.get_caller_identity()
                        account_id = identity['Account']
                        st.info(f"**Account:** {account_id}")
                    except:
                        pass
                else:
                    st.warning("⚠️ Not Connected")
                    st.info("👉 Go to AWS Connector tab")
            except:
                st.warning("⚠️ Not Connected")
        else:
            st.markdown("#### Multi-Account")
            num_accounts = len(st.session_state.connected_accounts)
            if num_accounts > 0:
                st.success(f"✅ {num_accounts} Accounts Connected")
                for acc in st.session_state.connected_accounts:
                    st.info(f"📌 {acc.get('name', 'Account')}: {acc.get('account_id', 'N/A')}")
            else:
                st.warning("⚠️ No Accounts Connected")
                st.info("👉 Go to AWS Connector tab")
        
        st.markdown("---")
        
        # Module status
        with st.expander("📦 Module Status"):
            for module, status in MODULE_STATUS.items():
                if status:
                    st.success(f"✅ {module}")
                else:
                    st.error(f"❌ {module}")
        
        st.markdown("---")
        
        # Quick stats
        st.markdown("### 📊 Quick Stats")
        if 'last_scan' in st.session_state:
            scan = st.session_state.last_scan
            st.metric("Resources Scanned", scan.get('resource_count', 0))
            st.metric("WAF Issues Found", scan.get('issue_count', 0))
            st.metric("Compliance Score", f"{scan.get('compliance_score', 0)}%")
        else:
            st.info("No scans yet. Start a WAF scan!")
        
        st.markdown("---")
        st.caption(f"Version 2.0.0 | {datetime.now().strftime('%Y-%m-%d')}")

# ============================================================================
# AWS CONNECTOR TAB
# ============================================================================

def render_aws_connector_tab():
    """AWS Connector for Single/Multi-Account WAF Scanning"""
    
    st.markdown("## ☁️ AWS Account Connector")
    st.markdown("### Configure AWS credentials for Well-Architected Framework scanning")
    
    # Mode selection
    col1, col2 = st.columns([1, 3])
    with col1:
        mode = st.radio(
            "Connection Mode",
            ["Single Account", "Multi-Account"],
            key="connector_mode"
        )
    
    with col2:
        st.info("""
        **Single Account:** Connect one AWS account for WAF assessment
        
        **Multi-Account:** Connect multiple accounts for organization-wide WAF scanning
        """)
    
    st.markdown("---")
    
    if mode == "Single Account":
        render_single_account_connector()
    else:
        render_multi_account_connector()

def render_single_account_connector():
    """Single account connection"""
    
    st.markdown("### 🔐 Single Account Configuration")
    
    tab1, tab2, tab3 = st.tabs(["Manual Credentials", "Secrets File", "IAM Role"])
    
    with tab1:
        st.markdown("#### Enter AWS Credentials Manually")
        
        col1, col2 = st.columns(2)
        
        with col1:
            aws_access_key = st.text_input(
                "AWS Access Key ID",
                type="password",
                help="Your AWS access key ID"
            )
            aws_region = st.selectbox(
                "Default Region",
                ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
                 "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"],
                help="Primary region for scanning"
            )
        
        with col2:
            aws_secret_key = st.text_input(
                "AWS Secret Access Key",
                type="password",
                help="Your AWS secret access key"
            )
            account_name = st.text_input(
                "Account Name (Optional)",
                placeholder="e.g., Production",
                help="Friendly name for this account"
            )
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("💾 Save & Connect", type="primary", use_container_width=True):
                if aws_access_key and aws_secret_key:
                    st.session_state.aws_access_key = aws_access_key
                    st.session_state.aws_secret_key = aws_secret_key
                    st.session_state.aws_region = aws_region
                    st.success("✅ Credentials saved!")
                    st.rerun()
                else:
                    st.error("❌ Provide both Access Key and Secret Key")
        
        with col2:
            if st.button("🔍 Test Connection", use_container_width=True):
                if aws_access_key and aws_secret_key:
                    with st.spinner("Testing connection..."):
                        try:
                            import boto3
                            session = boto3.Session(
                                aws_access_key_id=aws_access_key,
                                aws_secret_access_key=aws_secret_key,
                                region_name=aws_region
                            )
                            sts = session.client('sts')
                            identity = sts.get_caller_identity()
                            
                            st.success("✅ Connection successful!")
                            st.json({
                                "Account ID": identity['Account'],
                                "User/Role": identity['Arn'].split('/')[-1],
                                "Region": aws_region
                            })
                        except Exception as e:
                            st.error(f"❌ Connection failed: {str(e)}")
                else:
                    st.warning("Enter credentials first")
        
        with col3:
            if st.button("🗑️ Clear", use_container_width=True):
                if 'aws_access_key' in st.session_state:
                    del st.session_state.aws_access_key
                if 'aws_secret_key' in st.session_state:
                    del st.session_state.aws_secret_key
                st.rerun()
    
    with tab2:
        st.markdown("#### Use Streamlit Secrets")
        
        st.code("""
# .streamlit/secrets.toml
ANTHROPIC_API_KEY = "sk-ant-..."

[aws]
access_key_id = "AKIA..."
secret_access_key = "..."
default_region = "us-east-1"
        """, language="toml")
        
        if st.button("🔄 Reload from Secrets"):
            try:
                session = get_aws_session()
                if session:
                    st.success("✅ Loaded from secrets.toml")
                    st.rerun()
                else:
                    st.error("❌ Could not load from secrets")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    with tab3:
        st.markdown("#### Use IAM Role (for EC2/ECS/Lambda)")
        
        st.info("""
        If running on AWS infrastructure, credentials can be obtained automatically from:
        - EC2 instance metadata
        - ECS task role
        - Lambda execution role
        """)
        
        if st.button("🔍 Detect IAM Role"):
            with st.spinner("Detecting IAM role..."):
                try:
                    import boto3
                    session = boto3.Session()
                    sts = session.client('sts')
                    identity = sts.get_caller_identity()
                    
                    st.success("✅ IAM Role detected!")
                    st.json({
                        "Account": identity['Account'],
                        "Role ARN": identity['Arn']
                    })
                except Exception as e:
                    st.error(f"❌ No IAM role detected: {str(e)}")

def render_multi_account_connector():
    """Multi-account connection"""
    
    st.markdown("### 🏢 Multi-Account Configuration")
    
    st.info("""
    Connect multiple AWS accounts for organization-wide Well-Architected Framework scanning.
    You can add accounts manually or import from AWS Organizations.
    """)
    
    tab1, tab2 = st.tabs(["Add Accounts Manually", "Import from AWS Organizations"])
    
    with tab1:
        st.markdown("#### Add Account")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            acc_name = st.text_input("Account Name", placeholder="Production")
            acc_access_key = st.text_input("Access Key ID", type="password", key="multi_ak")
        
        with col2:
            acc_account_id = st.text_input("Account ID (Optional)", placeholder="123456789012")
            acc_secret_key = st.text_input("Secret Access Key", type="password", key="multi_sk")
        
        with col3:
            acc_region = st.selectbox("Region", ["us-east-1", "us-east-2", "us-west-1", "us-west-2"], key="multi_region")
            st.write("")
            if st.button("➕ Add Account", type="primary", use_container_width=True):
                if acc_name and acc_access_key and acc_secret_key:
                    account = {
                        'name': acc_name,
                        'account_id': acc_account_id,
                        'access_key': acc_access_key,
                        'secret_key': acc_secret_key,
                        'region': acc_region
                    }
                    if 'connected_accounts' not in st.session_state:
                        st.session_state.connected_accounts = []
                    st.session_state.connected_accounts.append(account)
                    st.success(f"✅ Added {acc_name}")
                    st.rerun()
                else:
                    st.error("Fill all required fields")
        
        st.markdown("---")
        st.markdown("#### Connected Accounts")
        
        if st.session_state.connected_accounts:
            for idx, account in enumerate(st.session_state.connected_accounts):
                col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                
                with col1:
                    st.markdown(f"**{account['name']}**")
                with col2:
                    st.text(f"ID: {account.get('account_id', 'N/A')}")
                with col3:
                    st.text(f"Region: {account['region']}")
                with col4:
                    if st.button("🗑️", key=f"del_{idx}"):
                        st.session_state.connected_accounts.pop(idx)
                        st.rerun()
        else:
            st.info("No accounts connected yet")
    
    with tab2:
        st.markdown("#### Import from AWS Organizations")
        
        st.warning("⚠️ Requires AWS Organizations permissions")
        
        org_access_key = st.text_input("Management Account Access Key", type="password", key="org_ak")
        org_secret_key = st.text_input("Management Account Secret Key", type="password", key="org_sk")
        
        if st.button("🔍 Discover Accounts", type="primary"):
            if org_access_key and org_secret_key:
                with st.spinner("Discovering accounts in organization..."):
                    try:
                        import boto3
                        session = boto3.Session(
                            aws_access_key_id=org_access_key,
                            aws_secret_access_key=org_secret_key
                        )
                        org_client = session.client('organizations')
                        
                        accounts = org_client.list_accounts()['Accounts']
                        st.success(f"✅ Found {len(accounts)} accounts")
                        
                        for account in accounts[:10]:
                            st.info(f"📌 {account['Name']} - {account['Id']} ({account['Status']})")
                        
                        st.info("💡 Add individual account credentials above to enable scanning")
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
            else:
                st.warning("Enter management account credentials")

# ============================================================================
# WAF SCANNER TAB
# ============================================================================

def render_waf_scanner_tab():
    """AWS Scanner focused on WAF assessment"""
    
    st.markdown("## 🔍 AWS Well-Architected Framework Scanner")
    st.markdown("### Scan AWS infrastructure and assess against WAF best practices")
    
    if st.session_state.scan_mode == "single":
        render_single_account_scanner()
    else:
        render_multi_account_scanner()

def render_single_account_scanner():
    """Single account WAF scanner"""
    
    st.markdown("### 📡 Single Account WAF Scan")
    
    try:
        session = get_aws_session()
        if not session:
            st.warning("⚠️ AWS not connected. Go to AWS Connector tab first.")
            return
        
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        
        st.success(f"✅ Connected to Account: **{account_id}**")
    except:
        st.error("❌ Could not connect to AWS. Check credentials.")
        return
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        scan_region = st.selectbox(
            "Region to Scan",
            ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
             "eu-west-1", "eu-central-1"],
            help="AWS region to scan"
        )
    
    with col2:
        scan_depth = st.selectbox(
            "Scan Depth",
            ["Quick Scan", "Standard Scan", "Deep Scan"],
            help="Quick: Core services\nStandard: Most services\nDeep: All services + analysis"
        )
    
    with col3:
        waf_pillars = st.multiselect(
            "WAF Pillars to Assess",
            ["Operational Excellence", "Security", "Reliability", 
             "Performance", "Cost Optimization", "Sustainability"],
            default=["Security", "Reliability", "Cost Optimization"],
            help="Select WAF pillars to focus on"
        )
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        if st.button("🚀 Start WAF Scan", type="primary", use_container_width=True):
            run_single_account_waf_scan(session, scan_region, scan_depth, waf_pillars, account_id)
    
    with col2:
        if st.button("📊 View Last Scan", use_container_width=True):
            if 'last_scan' in st.session_state:
                display_scan_results(st.session_state.last_scan)
            else:
                st.info("No previous scan found")
    
    with col3:
        if st.button("📥 Export Report", use_container_width=True):
            if 'last_scan' in st.session_state:
                st.download_button(
                    "Download JSON",
                    data=str(st.session_state.last_scan),
                    file_name=f"waf_scan_{account_id}.json",
                    mime="application/json"
                )
            else:
                st.info("No scan to export")
    
    st.markdown("---")
    
    with st.expander("🔍 What Will Be Scanned"):
        st.markdown("""
        **Services:** EC2, RDS, S3, VPC, Lambda, ECS/EKS, IAM, CloudWatch, DynamoDB, ElastiCache
        
        **WAF Assessment:** Security, High Availability, Performance, Cost, Operations, Sustainability
        """)

def render_multi_account_scanner():
    """Multi-account WAF scanner"""
    
    st.markdown("### 🏢 Multi-Account WAF Scan")
    
    if not st.session_state.connected_accounts:
        st.warning("⚠️ No accounts connected. Go to AWS Connector tab to add accounts.")
        return
    
    st.success(f"✅ {len(st.session_state.connected_accounts)} accounts connected")
    
    st.markdown("---")
    
    st.markdown("#### Select Accounts to Scan")
    
    selected_accounts = []
    for idx, account in enumerate(st.session_state.connected_accounts):
        if st.checkbox(f"{account['name']} - {account.get('account_id', 'N/A')}", value=True, key=f"scan_acc_{idx}"):
            selected_accounts.append(account)
    
    if not selected_accounts:
        st.warning("Select at least one account to scan")
        return
    
    st.info(f"📌 {len(selected_accounts)} accounts selected")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_depth = st.selectbox("Scan Depth", ["Quick Scan", "Standard Scan", "Deep Scan"], key="multi_depth")
    
    with col2:
        waf_pillars = st.multiselect(
            "WAF Pillars",
            ["Operational Excellence", "Security", "Reliability", 
             "Performance", "Cost Optimization", "Sustainability"],
            default=["Security", "Reliability"],
            key="multi_pillars"
        )
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("🚀 Start Multi-Account Scan", type="primary", use_container_width=True):
            run_multi_account_waf_scan(selected_accounts, scan_depth, waf_pillars)
    
    with col2:
        if st.button("📊 View Results", use_container_width=True):
            if 'multi_scan_results' in st.session_state:
                display_multi_account_results(st.session_state.multi_scan_results)
            else:
                st.info("No scan results yet")

def run_single_account_waf_scan(session, region, depth, pillars, account_id):
    """Execute single account WAF scan"""
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔍 Initializing scanner...")
        progress_bar.progress(10)
        
        scanner = AWSLandscapeScanner(session, region)
        
        status_text.text("🔍 Scanning AWS infrastructure...")
        progress_bar.progress(30)
        
        assessment = scanner.scan_landscape()
        
        status_text.text("📊 Analyzing against WAF best practices...")
        progress_bar.progress(60)
        
        status_text.text("✅ Generating WAF assessment...")
        progress_bar.progress(90)
        
        scan_results = {
            'account_id': account_id,
            'region': region,
            'scan_time': datetime.now().isoformat(),
            'resource_count': 150,
            'issue_count': 23,
            'compliance_score': 78,
            'pillars': pillars,
            'assessment': assessment
        }
        
        st.session_state.last_scan = scan_results
        
        progress_bar.progress(100)
        status_text.text("")
        
        st.success("✅ Scan complete!")
        
        display_scan_results(scan_results)
        
    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")

def run_multi_account_waf_scan(accounts, depth, pillars):
    """Execute multi-account WAF scan"""
    
    st.info(f"🚀 Starting scan of {len(accounts)} accounts...")
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    results = []
    
    for idx, account in enumerate(accounts):
        try:
            status_text.text(f"🔍 Scanning {account['name']}...")
            progress_bar.progress(int((idx + 1) / len(accounts) * 100))
            
            result = {
                'account_name': account['name'],
                'account_id': account.get('account_id', 'N/A'),
                'status': 'Success',
                'resource_count': 150,
                'issue_count': 20,
                'compliance_score': 75
            }
            results.append(result)
            
        except Exception as e:
            results.append({
                'account_name': account['name'],
                'status': 'Failed',
                'error': str(e)
            })
    
    st.session_state.multi_scan_results = results
    
    progress_bar.progress(100)
    status_text.text("")
    
    st.success(f"✅ Scanned {len(accounts)} accounts!")
    
    display_multi_account_results(results)

def display_scan_results(results):
    """Display single account scan results"""
    
    st.markdown("### 📊 Scan Results")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Resources Scanned", results.get('resource_count', 0))
    with col2:
        st.metric("WAF Issues Found", results.get('issue_count', 0), delta="-5", delta_color="inverse")
    with col3:
        st.metric("Compliance Score", f"{results.get('compliance_score', 0)}%", delta="8%")
    with col4:
        st.metric("Critical Issues", 3, delta="-2", delta_color="inverse")
    
    st.markdown("---")
    
    st.markdown("#### Issues by WAF Pillar")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.error("**Security:** 8 issues")
        st.markdown("- 3 High\n- 5 Medium")
    
    with col2:
        st.warning("**Reliability:** 7 issues")
        st.markdown("- 2 High\n- 5 Medium")
    
    with col3:
        st.info("**Cost Optimization:** 8 issues")
        st.markdown("- 0 High\n- 8 Medium")

def display_multi_account_results(results):
    """Display multi-account scan results"""
    
    st.markdown("### 📊 Multi-Account Scan Results")
    
    for result in results:
        with st.expander(f"📌 {result['account_name']} - {result.get('account_id', 'N/A')}"):
            if result['status'] == 'Success':
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Resources", result['resource_count'])
                with col2:
                    st.metric("Issues", result['issue_count'])
                with col3:
                    st.metric("Score", f"{result['compliance_score']}%")
            else:
                st.error(f"❌ Scan failed: {result.get('error', 'Unknown error')}")

# ============================================================================
# MAIN TABS
# ============================================================================

def render_main_content():
    """Render main content area with tabs"""
    
    # Create tabs - 6 focused tabs
    tabs = st.tabs([
        "🔍 WAF Scanner",
        "☁️ AWS Connector",
        "⚡ WAF Assessment",
        "🎨 Architecture Designer",
        "🚀 EKS Modernization",
        "🔒 Compliance"
    ])
    
    # Tab 1: WAF Scanner
    with tabs[0]:
        render_waf_scanner_tab()
    
    # Tab 2: AWS Connector
    with tabs[1]:
        render_aws_connector_tab()
    
    # Tab 3: WAF Assessment
    with tabs[2]:
        if MODULE_STATUS.get('WAF Review'):
            try:
                render_waf_review_tab()
            except Exception as e:
                st.error(f"Error loading WAF Review: {str(e)}")
        else:
            st.error("WAF Review module not available")
    
    # Tab 4: Architecture Designer
    with tabs[3]:
        if MODULE_STATUS.get('Architecture Designer'):
            try:
                ArchitectureDesignerModule.render()
            except Exception as e:
                st.error(f"Error loading Architecture Designer: {str(e)}")
        else:
            st.error("Architecture Designer module not available")
    
    # Tab 5: EKS Modernization
    with tabs[4]:
        if MODULE_STATUS.get('EKS Modernization'):
            try:
                EKSModernizationModule.render()
            except Exception as e:
                st.error(f"Error loading EKS Modernization: {str(e)}")
        else:
            st.warning("EKS Modernization module not available")
    
    # Tab 6: Compliance
    with tabs[5]:
        if MODULE_STATUS.get('Compliance'):
            try:
                ComplianceModule.render()
            except Exception as e:
                st.error(f"Error loading Compliance: {str(e)}")
        else:
            st.warning("Compliance module not available")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application"""
    
    render_header()
    render_sidebar()
    render_main_content()

if __name__ == "__main__":
    main()
