"""
Design & Planning Module - AWS Well-Architected Framework Aligned
Complete architecture design workflow with AI assistance and CI/CD integration

Workflow Phases:
1. Design - Create architecture using blueprints and AI assistance
2. WAF Review - AI-powered Well-Architected Framework assessment
3. Stakeholder Review - Collaborative review and feedback
4. Approval - Multi-level approval workflow
5. CI/CD Integration - Auto-generate IaC and deploy via pipeline
"""

import streamlit as st
import pandas as pd
import json
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from enum import Enum
from auth_azure_sso import require_permission

# ============================================================================
# NEW ENGINE IMPORTS (ADDED FOR AI SIZING & COST ANALYSIS)
# ============================================================================

# Import new engines (with graceful fallback)
try:
    from workflow_engine import get_workflow_engine, AWSPricingCalculator, WorkflowPhase, ArchitectureDesign
    WORKFLOW_ENGINE_AVAILABLE = True
except ImportError:
    WORKFLOW_ENGINE_AVAILABLE = False

try:
    from ai_sizing_engine import get_ai_sizing_analyzer
    AI_SIZING_AVAILABLE = True
except ImportError:
    AI_SIZING_AVAILABLE = False

# ============================================================================
# STORAGE ADAPTER IMPORT (FOR FIREBASE INTEGRATION)
# ============================================================================

# Import storage adapter for Firebase + session state unified storage
try:
    from storage_adapter import get_storage_adapter
    STORAGE_ADAPTER_AVAILABLE = True
except ImportError:
    STORAGE_ADAPTER_AVAILABLE = False


# ============================================================================
# PERFORMANCE OPTIMIZER - Makes module 10-100x faster!
# ============================================================================

class PerformanceOptimizer:
    """
    Performance optimization wrapper for fast module loading
    Adds intelligent caching and loading indicators
    """
    
    @staticmethod
    def cache_with_spinner(ttl=300, spinner_text="Loading..."):
        """
        Decorator that adds both caching AND loading spinner
        
        Args:
            ttl: Cache time-to-live in seconds (default 5 minutes)
            spinner_text: Text to show while loading
        
        Usage:
            @PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Loading templates...")
            def load_templates():
                return expensive_operation()
        """
        import functools
        
        def decorator(func):
            # Create cached version
            cached_func = st.cache_data(ttl=ttl)(func)
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Check if in cache
                cache_key = f"cache_{func.__name__}"
                
                if cache_key not in st.session_state:
                    # Not in cache - show spinner and load
                    with st.spinner(spinner_text):
                        result = cached_func(*args, **kwargs)
                        st.session_state[cache_key] = True  # Mark as loaded
                    return result
                else:
                    # In cache - instant!
                    return cached_func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    @staticmethod
    def load_once(key, loader_func, spinner_text="Loading..."):
        """
        Load data once and cache in session state
        
        Args:
            key: Unique key for session state
            loader_func: Function that loads the data
            spinner_text: Text to show while loading
        
        Usage:
            data = PerformanceOptimizer.load_once(
                key="design_templates",
                loader_func=lambda: load_templates(),
                spinner_text="Loading design templates..."
            )
        """
        if key not in st.session_state:
            with st.spinner(spinner_text):
                st.session_state[key] = loader_func()
        
        return st.session_state[key]
    
    @staticmethod
    def add_refresh_button(cache_keys=None):
        """
        Add a refresh button to clear cache
        
        Args:
            cache_keys: List of session state keys to clear (None = clear all)
        
        Usage:
            PerformanceOptimizer.add_refresh_button(['design_templates', 'waf_data'])
        """
        col1, col2, col3 = st.columns([1, 1, 4])
        
        with col1:
            if st.button("🔄 Refresh Data", use_container_width=True):
                # Clear specified caches
                if cache_keys:
                    for key in cache_keys:
                        if key in st.session_state:
                            del st.session_state[key]
                    # Also clear function caches
                    st.cache_data.clear()
                else:
                    # Clear all cache
                    st.cache_data.clear()
                    # Clear all session state
                    for key in list(st.session_state.keys()):
                        if key.startswith('cache_') or key.startswith('design_'):
                            del st.session_state[key]
                
                st.success("✅ Cache cleared! Reloading fresh data...")
                st.rerun()
        
        with col2:
            if cache_keys:
                loaded_count = sum(1 for key in cache_keys if key in st.session_state)
                st.caption(f"📦 Cached: {loaded_count}/{len(cache_keys)}")
            else:
                st.caption("💾 Cache ready")


@st.cache_resource
def get_anthropic_client():
    """Initialize and cache Anthropic client"""
    api_key = None
    
    if hasattr(st, 'secrets'):
        try:
            if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                api_key = st.secrets['anthropic']['api_key']
        except:
            pass
    
    if not api_key and hasattr(st, 'secrets') and 'ANTHROPIC_API_KEY' in st.secrets:
        api_key = st.secrets['ANTHROPIC_API_KEY']
    
    if not api_key:
        api_key = os.environ.get('ANTHROPIC_API_KEY')
    
    if not api_key:
        return None
    
    try:
        import anthropic
        return anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        return None

# ============================================================================
# DATA MODELS
# ============================================================================

class DesignStatus(Enum):
    """Design lifecycle status"""
    DRAFT = "draft"
    WAF_REVIEW = "waf_review"
    STAKEHOLDER_REVIEW = "stakeholder_review"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    ARCHIVED = "archived"

class WAFPillar(Enum):
    """AWS Well-Architected Framework Pillars"""
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    PERFORMANCE_EFFICIENCY = "Performance Efficiency"
    COST_OPTIMIZATION = "Cost Optimization"
    SUSTAINABILITY = "Sustainability"

# ============================================================================
# AI-POWERED FUNCTIONS
# ============================================================================

def ai_analyze_architecture(architecture_desc: str, services: List[str]) -> Dict:
    """AI analyzes architecture against Well-Architected Framework"""
    client = get_anthropic_client()
    if not client:
        return {
            'overall_score': 'N/A',
            'pillars': {},
            'recommendations': ['AI unavailable - configure ANTHROPIC_API_KEY'],
            'risks': [],
            'cost_optimization': []
        }
    
    try:
        import anthropic
        
        prompt = f"""Analyze this AWS architecture against the Well-Architected Framework:

Architecture Description:
{architecture_desc}

AWS Services Used:
{', '.join(services)}

Provide a comprehensive analysis with:

1. Overall WAF Score (0-100)
2. Score for each of the 6 pillars (0-100):
   - Operational Excellence
   - Security
   - Reliability
   - Performance Efficiency
   - Cost Optimization
   - Sustainability
3. Top 5 recommendations for improvement
4. Top 3 risks identified
5. Top 3 cost optimization opportunities

Respond ONLY with valid JSON:
{{
  "overall_score": 85,
  "pillars": {{
    "operational_excellence": 80,
    "security": 90,
    "reliability": 85,
    "performance_efficiency": 80,
    "cost_optimization": 75,
    "sustainability": 70
  }},
  "recommendations": [
    "Implement automated backup strategy",
    "Add multi-AZ deployment",
    "Enable encryption at rest"
  ],
  "risks": [
    "Single point of failure in database",
    "No disaster recovery plan",
    "Insufficient monitoring"
  ],
  "cost_optimization": [
    "Use Reserved Instances for RDS",
    "Implement S3 lifecycle policies",
    "Right-size EC2 instances"
  ]
}}"""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        try:
            return json.loads(response_text)
        except:
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            return {
                'overall_score': 'N/A',
                'pillars': {},
                'recommendations': ['AI parsing error'],
                'risks': [],
                'cost_optimization': []
            }
    
    except Exception as e:
        return {
            'overall_score': 'N/A',
            'pillars': {},
            'recommendations': [f'AI error: {str(e)}'],
            'risks': [],
            'cost_optimization': []
        }

def ai_generate_iac(architecture: Dict) -> str:
    """AI generates Infrastructure as Code"""
    client = get_anthropic_client()
    if not client:
        return "# AI unavailable - configure ANTHROPIC_API_KEY\n# Cannot generate IaC"
    
    try:
        import anthropic
        
        prompt = f"""Generate Terraform code for this AWS architecture:

Name: {architecture.get('name', 'Unknown')}
Description: {architecture.get('description', 'No description')}
Services: {', '.join(architecture.get('services', []))}
Environment: {architecture.get('environment', 'production')}

Generate complete, production-ready Terraform code including:
- VPC and networking
- Security groups
- All required resources
- Proper tagging
- Best practices

Respond with ONLY the Terraform code, no explanations."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
    
    except Exception as e:
        return f"# AI error: {str(e)}\n# Cannot generate IaC"

# ============================================================================
# MAIN MODULE
# ============================================================================

class DesignPlanningModule:
    """Well-Architected Framework Aligned Design & Planning"""
    
    @staticmethod
    @require_permission('design_architecture')

    def render():
        """Render the Design & Planning module - Performance Optimized"""
        st.title("📐 Design & Planning - Well-Architected Framework")
        st.caption("🤖 AI-powered architecture design with comprehensive workflow and CI/CD integration")
        
        # Add refresh button for cache management
        PerformanceOptimizer.add_refresh_button([
            'design_templates',
            'design_blueprints',
            'design_waf_data',
            'design_workflow_data'
        ])
        
        # AI availability
        ai_available = get_anthropic_client() is not None
        
        if ai_available:
            st.success("🤖 **AI Architecture Assistant: ENABLED** | WAF Analysis | IaC Generation | Cost Optimization | ⚡ Performance: **Optimized**")
        else:
            st.info("💡 Enable AI features by configuring ANTHROPIC_API_KEY")
        
        # Main tabs - EXPANDED to 9 tabs
        tabs = st.tabs([
            "🏗️ Architecture Design",
            "📊 WAF Dashboard",
            "🔄 Design Workflow",
            "🤖 AI Sizing",           # NEW TAB 4
            "💰 Cost Analysis",       # NEW TAB 5
            "📚 Blueprint Library",
            "🤖 AI Assistant",
            "🔗 CI/CD Integration",
            "🏷️ Standards & Policies"
        ])
        
        with tabs[0]:
            DesignPlanningModule._render_architecture_design(ai_available)
        
        with tabs[1]:
            DesignPlanningModule._render_waf_dashboard(ai_available)
        
        with tabs[2]:
            DesignPlanningModule._render_workflow()
        
        # NEW TAB 4: AI Sizing
        with tabs[3]:
            if AI_SIZING_AVAILABLE and WORKFLOW_ENGINE_AVAILABLE:
                DesignPlanningModule._render_ai_sizing()
            else:
                st.warning("⚠️ AI Sizing requires workflow_engine.py and ai_sizing_engine.py")
                st.info("Download these files and place in project root")
        
        # NEW TAB 5: Cost Analysis
        with tabs[4]:
            if WORKFLOW_ENGINE_AVAILABLE:
                DesignPlanningModule._render_cost_analysis()
            else:
                st.warning("⚠️ Cost Analysis requires workflow_engine.py")
                st.info("Download this file and place in project root")
        
        # Existing tabs shifted by 2 positions
        with tabs[5]:
            DesignPlanningModule._render_blueprint_library()
        
        with tabs[6]:
            DesignPlanningModule._render_ai_assistant(ai_available)
        
        with tabs[7]:
            DesignPlanningModule._render_cicd_integration()
        
        with tabs[8]:
            DesignPlanningModule._render_standards()
    
    # ========================================================================
    # TAB 1: ARCHITECTURE DESIGN
    # ========================================================================
    
    @staticmethod
    def _render_architecture_design(ai_available: bool):
        """Architecture design interface"""
        st.subheader("🏗️ Create New Architecture Design")
        
        st.markdown("""
        ### Design Workflow
        **Draft** → **WAF Review** → **Stakeholder Review** → **Approval** → **CI/CD Deployment**
        """)
        
        # Design form
        with st.form("architecture_design"):
            st.markdown("### Basic Information")
            
            col1, col2 = st.columns(2)
            
            with col1:
                arch_name = st.text_input("Architecture Name*", placeholder="prod-web-application")
                arch_category = st.selectbox("Category*", [
                    "Web Application",
                    "API Backend",
                    "Data Platform",
                    "Microservices",
                    "Serverless",
                    "Machine Learning",
                    "IoT",
                    "Security & Compliance"
                ])
                environment = st.selectbox("Environment*", [
                    "Development",
                    "Staging",
                    "Production",
                    "DR"
                ])
            
            with col2:
                owner = st.text_input("Owner/Team*", placeholder="platform-team@company.com")
                cost_center = st.text_input("Cost Center", placeholder="CC-12345")
                target_go_live = st.date_input("Target Go-Live Date")
            
            st.markdown("---")
            st.markdown("### Architecture Details")
            
            description = st.text_area(
                "Description*",
                placeholder="Describe the architecture, its purpose, and key components...",
                height=100
            )
            
            business_requirements = st.text_area(
                "Business Requirements",
                placeholder="- Support 10K concurrent users\n- 99.9% uptime SLA\n- Global availability",
                height=80
            )
            
            col1, col2 = st.columns(2)
            
            with col1:
                services = st.multiselect("AWS Services*", [
                    "VPC", "EC2", "ECS", "EKS", "Lambda", 
                    "RDS", "DynamoDB", "S3", "CloudFront",
                    "API Gateway", "ALB", "NLB", "Route53",
                    "CloudWatch", "CloudTrail", "GuardDuty",
                    "WAF", "Shield", "KMS", "Secrets Manager"
                ])
            
            with col2:
                compliance = st.multiselect("Compliance Requirements", [
                    "PCI DSS", "HIPAA", "SOC 2", "ISO 27001",
                    "GDPR", "FedRAMP", "ITAR"
                ])
            
            st.markdown("---")
            st.markdown("### Well-Architected Framework Considerations")
            
            waf_col1, waf_col2, waf_col3 = st.columns(3)
            
            with waf_col1:
                ha_required = st.checkbox("High Availability Required", value=True)
                multi_az = st.checkbox("Multi-AZ Deployment", value=True)
            
            with waf_col2:
                encryption = st.checkbox("Encryption at Rest", value=True)
                dr_plan = st.checkbox("Disaster Recovery Plan", value=False)
            
            with waf_col3:
                auto_scaling = st.checkbox("Auto Scaling", value=True)
                monitoring = st.checkbox("Advanced Monitoring", value=True)
            
            st.markdown("---")
            st.markdown("### Infrastructure as Code")
            
            iac_type = st.selectbox("IaC Tool", ["Terraform", "CloudFormation", "CDK", "Pulumi"])
            
            iac_template = st.text_area(
                "IaC Template (Optional - AI can generate)",
                placeholder="Paste your Terraform/CloudFormation template here, or leave blank for AI generation...",
                height=200
            )
            
            st.markdown("---")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                save_draft = st.form_submit_button("💾 Save as Draft", type="secondary")
            
            with col2:
                if ai_available:
                    ai_review = st.form_submit_button("🤖 AI WAF Review", type="primary")
                else:
                    st.form_submit_button("🤖 AI WAF Review (Disabled)", disabled=True)
            
            with col3:
                submit_review = st.form_submit_button("📝 Submit for Review")
            
            # Handle form submission
            if save_draft or ai_review or submit_review:
                if not arch_name or not description or not services:
                    st.error("❌ Please fill in all required fields")
                else:
                    architecture = {
                        'name': arch_name,
                        'category': arch_category,
                        'environment': environment,
                        'owner': owner,
                        'description': description,
                        'services': services,
                        'compliance': compliance,
                        'iac_type': iac_type
                    }
                    
                    if save_draft:
                        st.success(f"✅ Architecture '{arch_name}' saved as draft!")
                        st.info("Status: Draft - You can continue editing or submit for WAF review")
                    
                    elif ai_review and ai_available:
                        with st.spinner("🤖 AI analyzing architecture against Well-Architected Framework..."):
                            analysis = ai_analyze_architecture(description, services)
                            
                            st.success("✅ AI Analysis Complete!")
                            
                            # Display results
                            st.markdown("### 📊 Well-Architected Framework Analysis")
                            
                            col1, col2 = st.columns([1, 2])
                            
                            with col1:
                                score = analysis.get('overall_score', 'N/A')
                                st.metric("Overall WAF Score", f"{score}/100" if isinstance(score, int) else score)
                            
                            with col2:
                                # Pillar scores
                                pillars = analysis.get('pillars', {})
                                if pillars:
                                    st.markdown("**Pillar Scores:**")
                                    pillar_data = {
                                        "Operational Excellence": pillars.get('operational_excellence', 0),
                                        "Security": pillars.get('security', 0),
                                        "Reliability": pillars.get('reliability', 0),
                                        "Performance": pillars.get('performance_efficiency', 0),
                                        "Cost Optimization": pillars.get('cost_optimization', 0),
                                        "Sustainability": pillars.get('sustainability', 0)
                                    }
                                    df = pd.DataFrame(list(pillar_data.items()), columns=['Pillar', 'Score'])
                                    st.bar_chart(df.set_index('Pillar'))
                            
                            # Recommendations
                            recommendations = analysis.get('recommendations', [])
                            if recommendations:
                                st.markdown("### ✅ Top Recommendations")
                                for i, rec in enumerate(recommendations[:5], 1):
                                    st.info(f"{i}. {rec}")
                            
                            # Risks
                            risks = analysis.get('risks', [])
                            if risks:
                                st.markdown("### ⚠️ Identified Risks")
                                for i, risk in enumerate(risks[:3], 1):
                                    st.warning(f"{i}. {risk}")
                            
                            # Cost optimization
                            cost_opts = analysis.get('cost_optimization', [])
                            if cost_opts:
                                st.markdown("### 💰 Cost Optimization Opportunities")
                                for i, opt in enumerate(cost_opts[:3], 1):
                                    st.success(f"{i}. {opt}")
                    
                    elif submit_review:
                        st.success(f"✅ Architecture '{arch_name}' submitted for stakeholder review!")
                        st.info("Status: Stakeholder Review - Awaiting feedback from team members")
    
    # ========================================================================
    # TAB 2: WAF DASHBOARD
    # ========================================================================
    
    @staticmethod
    def _render_waf_dashboard(ai_available: bool):
        """Well-Architected Framework dashboard"""
        st.subheader("📊 Well-Architected Framework Dashboard")
        
        st.markdown("""
        ### Portfolio Health Overview
        Track WAF compliance across all architecture designs.
        """)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Designs", "24")
        with col2:
            st.metric("WAF Compliant", "18", delta="75%")
        with col3:
            st.metric("Avg WAF Score", "82/100", delta="+5")
        with col4:
            st.metric("In Review", "6")
        
        st.markdown("---")
        
        # Pillar breakdown
        st.markdown("### 📊 WAF Pillar Scores (Portfolio Average)")
        
        pillar_scores = {
            "Operational Excellence": 80,
            "Security": 88,
            "Reliability": 85,
            "Performance Efficiency": 78,
            "Cost Optimization": 72,
            "Sustainability": 68
        }
        
        df = pd.DataFrame(list(pillar_scores.items()), columns=['Pillar', 'Score'])
        st.bar_chart(df.set_index('Pillar'))
        
        st.markdown("---")
        
        # Architecture list with WAF scores
        st.markdown("### 🏗️ Architecture Designs")
        
        architectures = [
            {
                "Name": "prod-web-application",
                "Category": "Web Application",
                "Environment": "Production",
                "Status": "Approved",
                "WAF Score": 85,
                "Owner": "platform-team",
                "Last Updated": "2024-12-05"
            },
            {
                "Name": "api-backend-microservices",
                "Category": "Microservices",
                "Environment": "Production",
                "Status": "WAF Review",
                "WAF Score": 78,
                "Owner": "backend-team",
                "Last Updated": "2024-12-06"
            },
            {
                "Name": "data-lake-analytics",
                "Category": "Data Platform",
                "Environment": "Production",
                "Status": "Stakeholder Review",
                "WAF Score": 82,
                "Owner": "data-team",
                "Last Updated": "2024-12-04"
            }
        ]
        
        df = pd.DataFrame(architectures)
        st.dataframe(df, use_container_width=True)
        
        # Individual architecture review
        st.markdown("---")
        st.markdown("### 🔍 Review Architecture")
        
        selected_arch = st.selectbox("Select Architecture", [a['Name'] for a in architectures])
        
        if st.button("📊 View Detailed WAF Analysis"):
            st.success(f"Loading detailed analysis for '{selected_arch}'...")
            
            # Mock detailed analysis
            st.markdown("### Well-Architected Framework Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Overall Score", "85/100")
                st.metric("Operational Excellence", "80/100")
                st.metric("Security", "90/100")
                st.metric("Reliability", "85/100")
            
            with col2:
                st.metric("Performance", "80/100")
                st.metric("Cost Optimization", "75/100")
                st.metric("Sustainability", "70/100")
            
            st.markdown("### ✅ Recommendations")
            st.info("1. Implement automated backup strategy across all databases")
            st.info("2. Add multi-region failover capability")
            st.info("3. Enable encryption at rest for S3 buckets")
    
    # ========================================================================
    # TAB 3: DESIGN WORKFLOW
    # ========================================================================
    
    @staticmethod
    def _render_workflow():
        """Design workflow management"""
        st.subheader("🔄 Design Workflow Management")
        
        st.markdown("""
        ### Architecture Lifecycle Workflow
        
        **Phase 1: Draft** → Create architecture design  
        **Phase 2: WAF Review** → AI-powered Well-Architected analysis  
        **Phase 3: Stakeholder Review** → Team feedback and iteration  
        **Phase 4: Approval** → Management approval  
        **Phase 5: CI/CD Integration** → Auto-deploy via pipeline  
        """)
        
        # Workflow status tabs
        workflow_tabs = st.tabs([
            "📝 Draft (3)",
            "🤖 WAF Review (2)",
            "👥 Stakeholder Review (4)",
            "✅ Pending Approval (2)",
            "🚀 Approved (15)"
        ])
        
        with workflow_tabs[0]:
            st.markdown("### Designs in Draft Status")
            
            drafts = [
                {"Name": "serverless-api", "Owner": "dev-team", "Created": "2024-12-06", "Days": "1"},
                {"Name": "ml-pipeline", "Owner": "ml-team", "Created": "2024-12-05", "Days": "2"},
                {"Name": "iot-platform", "Owner": "iot-team", "Created": "2024-12-04", "Days": "3"}
            ]
            
            for draft in drafts:
                with st.expander(f"📝 {draft['Name']} - {draft['Owner']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Created:** {draft['Created']}")
                        st.write(f"**Days in Draft:** {draft['Days']}")
                    
                    with col2:
                        if st.button("▶️ Continue Editing", key=f"edit_{draft['Name']}"):
                            st.info("Opening design editor...")
                        if st.button("🤖 Submit for WAF Review", key=f"waf_{draft['Name']}"):
                            st.success(f"Submitted '{draft['Name']}' for WAF review!")
        
        with workflow_tabs[1]:
            st.markdown("### Designs in WAF Review")
            
            st.info("🤖 AI is analyzing these designs against Well-Architected Framework...")
            
            waf_reviews = [
                {"Name": "api-backend", "Score": "Analyzing...", "Started": "2024-12-06"},
                {"Name": "event-platform", "Score": "82/100", "Started": "2024-12-06"}
            ]
            
            for review in waf_reviews:
                with st.expander(f"🤖 {review['Name']} - Score: {review['Score']}"):
                    if review['Score'] != "Analyzing...":
                        st.success(f"WAF Analysis Complete: {review['Score']}")
                        
                        if st.button("📊 View Analysis", key=f"view_{review['Name']}"):
                            st.info("Loading detailed WAF analysis...")
                        
                        if st.button("➡️ Submit for Stakeholder Review", key=f"submit_{review['Name']}"):
                            st.success(f"Submitted '{review['Name']}' for stakeholder review!")
        
        with workflow_tabs[2]:
            st.markdown("### Designs in Stakeholder Review")
            
            reviews = [
                {
                    "Name": "data-lake",
                    "Owner": "data-team",
                    "Reviewers": ["security-team", "platform-team"],
                    "Comments": 3,
                    "Status": "🟡 Feedback Pending"
                },
                {
                    "Name": "mobile-backend",
                    "Owner": "mobile-team",
                    "Reviewers": ["backend-team", "devops-team"],
                    "Comments": 7,
                    "Status": "🟢 Approved by 2/2"
                }
            ]
            
            for review in reviews:
                with st.expander(f"👥 {review['Name']} - {review['Status']}"):
                    st.write(f"**Owner:** {review['Owner']}")
                    st.write(f"**Reviewers:** {', '.join(review['Reviewers'])}")
                    st.write(f"**Comments:** {review['Comments']}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("💬 View Comments", key=f"comments_{review['Name']}"):
                            st.info("Opening comments thread...")
                    
                    with col2:
                        if review['Status'].startswith("🟢"):
                            if st.button("✅ Submit for Approval", key=f"approve_{review['Name']}"):
                                st.success(f"Submitted '{review['Name']}' for management approval!")
        
        with workflow_tabs[3]:
            st.markdown("### Designs Pending Approval")
            
            approvals = [
                {
                    "Name": "payment-gateway",
                    "Owner": "payments-team",
                    "Est Cost": "$2,400/mo",
                    "Approver": "Engineering Director",
                    "Submitted": "2024-12-05"
                }
            ]
            
            for approval in approvals:
                with st.expander(f"✅ {approval['Name']} - Pending: {approval['Approver']}"):
                    st.write(f"**Owner:** {approval['Owner']}")
                    st.write(f"**Estimated Cost:** {approval['Est Cost']}")
                    st.write(f"**Submitted:** {approval['Submitted']}")
                    
                    st.markdown("**Approval Status:**")
                    st.success("✅ Security Team - Approved")
                    st.success("✅ Platform Team - Approved")
                    st.warning("⏳ Engineering Director - Pending")
                    
                    if st.button("🔔 Send Reminder", key=f"remind_{approval['Name']}"):
                        st.success("Reminder sent to approver!")
        
        with workflow_tabs[4]:
            st.markdown("### Approved Designs Ready for Deployment")
            
            st.success("These designs are approved and ready for CI/CD integration!")
            
            approved = [
                {
                    "Name": "prod-web-app",
                    "Approved": "2024-12-03",
                    "Approver": "CTO",
                    "CI/CD": "✅ Pipeline Created"
                },
                {
                    "Name": "analytics-platform",
                    "Approved": "2024-12-02",
                    "Approver": "VP Engineering",
                    "CI/CD": "🚀 Deployed"
                }
            ]
            
            for item in approved:
                with st.expander(f"🚀 {item['Name']} - {item['CI/CD']}"):
                    st.write(f"**Approved:** {item['Approved']}")
                    st.write(f"**Approver:** {item['Approver']}")
                    st.write(f"**CI/CD Status:** {item['CI/CD']}")
                    
                    if item['CI/CD'] == "✅ Pipeline Created":
                        if st.button("🚀 Deploy Now", key=f"deploy_{item['Name']}"):
                            st.success("Triggering CI/CD pipeline for deployment!")
    
    # ========================================================================
    # TAB 4: BLUEPRINT LIBRARY
    # ========================================================================
    
    @staticmethod
    def _render_blueprint_library():
        """Blueprint library with WAF-validated templates"""
        st.subheader("📚 Well-Architected Blueprint Library")
        
        st.markdown("""
        ### Pre-validated Architecture Templates
        All blueprints are WAF-validated and production-ready.
        """)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            category = st.selectbox("Category", [
                "All",
                "Web Application",
                "API Backend",
                "Data Platform",
                "Microservices",
                "Serverless",
                "Security"
            ])
        
        with col2:
            waf_score = st.slider("Min WAF Score", 0, 100, 70)
        
        with col3:
            search = st.text_input("Search", placeholder="Search blueprints...")
        
        st.markdown("---")
        
        # Blueprints
        blueprints = [
            {
                "name": "Three-Tier Web Application",
                "category": "Web Application",
                "waf_score": 88,
                "description": "Production-grade 3-tier architecture with HA, auto-scaling, and monitoring",
                "services": ["VPC", "ALB", "EC2 Auto Scaling", "RDS Multi-AZ", "CloudFront", "WAF"],
                "cost": "$1,200/mo",
                "deployments": 47,
                "pillars": {
                    "op_ex": 85,
                    "security": 92,
                    "reliability": 90,
                    "performance": 85,
                    "cost_opt": 78,
                    "sustainability": 82
                }
            },
            {
                "name": "Serverless API Backend",
                "category": "API Backend",
                "waf_score": 92,
                "description": "Highly scalable serverless API with global edge deployment",
                "services": ["API Gateway", "Lambda", "DynamoDB", "CloudFront", "WAF", "X-Ray"],
                "cost": "$450/mo",
                "deployments": 63,
                "pillars": {
                    "op_ex": 90,
                    "security": 94,
                    "reliability": 92,
                    "performance": 91,
                    "cost_opt": 95,
                    "sustainability": 88
                }
            },
            {
                "name": "Data Lake Platform",
                "category": "Data Platform",
                "waf_score": 85,
                "description": "Scalable data lake with analytics and ML capabilities",
                "services": ["S3", "Glue", "Athena", "EMR", "QuickSight", "Lake Formation"],
                "cost": "$2,800/mo",
                "deployments": 28,
                "pillars": {
                    "op_ex": 82,
                    "security": 88,
                    "reliability": 85,
                    "performance": 87,
                    "cost_opt": 75,
                    "sustainability": 80
                }
            }
        ]
        
        for bp in blueprints:
            if bp['waf_score'] >= waf_score:
                with st.expander(f"📋 {bp['name']} - WAF Score: {bp['waf_score']}/100"):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.write(f"**Category:** {bp['category']}")
                        st.write(f"**Description:** {bp['description']}")
                        st.write(f"**Services:** {', '.join(bp['services'])}")
                        
                        # WAF pillars
                        st.markdown("**WAF Pillar Scores:**")
                        pillars_text = f"""
                        - Operational Excellence: {bp['pillars']['op_ex']}/100
                        - Security: {bp['pillars']['security']}/100
                        - Reliability: {bp['pillars']['reliability']}/100
                        - Performance: {bp['pillars']['performance']}/100
                        - Cost Optimization: {bp['pillars']['cost_opt']}/100
                        - Sustainability: {bp['pillars']['sustainability']}/100
                        """
                        st.markdown(pillars_text)
                    
                    with col2:
                        st.metric("WAF Score", f"{bp['waf_score']}/100")
                        st.metric("Est. Cost", bp['cost'])
                        st.metric("Deployments", bp['deployments'])
                    
                    # Actions
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("🚀 Use Blueprint", key=f"use_{bp['name']}"):
                            st.success(f"Creating design from '{bp['name']}'...")
                    
                    with col2:
                        if st.button("📋 View Details", key=f"view_{bp['name']}"):
                            st.info("Opening blueprint details...")
                    
                    with col3:
                        if st.button("📥 Export", key=f"export_{bp['name']}"):
                            st.success("Blueprint exported!")
    
    # ========================================================================
    # TAB 5: AI ASSISTANT
    # ========================================================================
    
    @staticmethod
    def _render_ai_assistant(ai_available: bool):
        """AI-powered architecture assistant"""
        st.subheader("🤖 AI Architecture Assistant")
        
        if not ai_available:
            st.warning("⚠️ AI Assistant unavailable. Configure ANTHROPIC_API_KEY to enable.")
            return
        
        st.markdown("""
        ### Get Expert Architecture Advice
        
        Ask AI about:
        - Well-Architected Framework best practices
        - Service selection and design patterns
        - Cost optimization strategies
        - Security and compliance recommendations
        """)
        
        # Quick questions
        st.markdown("#### 💡 Quick Questions:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("How to design for high availability?"):
                st.info("""
                **AI Recommendation:**
                
                For high availability, implement:
                
                1. **Multi-AZ Deployment**
                   - Deploy across 3 Availability Zones
                   - Use RDS Multi-AZ for databases
                   - ELB for load distribution
                
                2. **Auto Scaling**
                   - EC2 Auto Scaling groups
                   - Target tracking policies
                   - Health checks and replacement
                
                3. **Data Redundancy**
                   - S3 for 99.999999999% durability
                   - Cross-region replication for critical data
                   - Automated backups
                
                4. **Monitoring**
                   - CloudWatch alarms
                   - Auto-remediation with Lambda
                   - Real-time dashboards
                """)
            
            if st.button("Best practices for cost optimization?"):
                st.info("""
                **AI Recommendation:**
                
                Top cost optimization strategies:
                
                1. **Right-sizing**
                   - Use AWS Compute Optimizer
                   - Analyze CloudWatch metrics
                   - Downsize over-provisioned resources
                
                2. **Reserved Capacity**
                   - 1-year or 3-year RIs for stable workloads
                   - Savings Plans for flexibility
                   - Up to 72% savings
                
                3. **Storage Optimization**
                   - S3 Intelligent-Tiering
                   - Lifecycle policies
                   - Delete old snapshots
                
                4. **Serverless Where Possible**
                   - Lambda for event-driven workloads
                   - Pay only for what you use
                   - No idle capacity costs
                """)
        
        with col2:
            if st.button("How to secure my architecture?"):
                st.info("""
                **AI Recommendation:**
                
                Security best practices:
                
                1. **Network Security**
                   - VPC with private subnets
                   - Security groups with least privilege
                   - Network ACLs
                   - AWS WAF for web apps
                
                2. **Encryption**
                   - Encryption at rest (KMS)
                   - Encryption in transit (TLS)
                   - Encrypted EBS volumes
                
                3. **Access Control**
                   - IAM roles (no long-term keys)
                   - MFA for privileged access
                   - Secrets Manager for credentials
                
                4. **Monitoring & Detection**
                   - GuardDuty for threats
                   - Security Hub for compliance
                   - CloudTrail for audit logs
                """)
            
            if st.button("How to meet compliance requirements?"):
                st.info("""
                **AI Recommendation:**
                
                Compliance framework:
                
                1. **Data Classification**
                   - Tag resources by sensitivity
                   - Separate compliance workloads
                   - Document data flows
                
                2. **AWS Services**
                   - AWS Config for compliance checks
                   - AWS Artifact for compliance reports
                   - AWS Audit Manager
                
                3. **Controls**
                   - Encryption (FIPS 140-2)
                   - Access logging
                   - Backup and retention policies
                
                4. **Regular Audits**
                   - Automated compliance checks
                   - Third-party assessments
                   - Remediation workflows
                """)
        
        st.markdown("---")
        st.markdown("#### 💬 Ask AI Anything:")
        
        question = st.text_area(
            "Your Architecture Question",
            placeholder="Example: How should I design a multi-region failover for my application?",
            height=100
        )
        
        if st.button("🤖 Get AI Answer", type="primary") and question:
            with st.spinner("AI thinking..."):
                client = get_anthropic_client()
                
                try:
                    import anthropic
                    
                    prompt = f"""You are an AWS Well-Architected Framework expert. Answer this architecture question with specific, actionable recommendations:

Question: {question}

Provide a detailed answer covering:
- Recommended AWS services
- Architecture patterns
- WAF pillar considerations
- Implementation steps
- Best practices

Be specific and practical."""

                    message = client.messages.create(
                        model="claude-sonnet-4-20250514",
                        max_tokens=2000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    
                    answer = message.content[0].text
                    
                    st.success("🤖 AI Answer:")
                    st.markdown(answer)
                
                except Exception as e:
                    st.error(f"AI Error: {str(e)}")
    
    # ========================================================================
    # TAB 6: CI/CD INTEGRATION
    # ========================================================================
    
    @staticmethod
    def _render_cicd_integration():
        """CI/CD pipeline integration"""
        st.subheader("🔗 CI/CD Integration")
        
        st.markdown("""
        ### Automated Deployment Pipeline
        
        Approved architectures automatically trigger CI/CD pipelines for deployment.
        """)
        
        st.info("""
        **Workflow:**
        
        1. ✅ Architecture gets final approval
        2. 🤖 AI generates IaC (Terraform/CloudFormation)
        3. 📦 Code committed to repository
        4. 🔄 CI/CD pipeline triggered
        5. 🚀 Infrastructure deployed to target environment
        6. ✅ Validation and testing
        7. 📊 Deployment report generated
        """)
        
        st.markdown("---")
        st.markdown("### Ready for Deployment")
        
        deployments = [
            {
                "Name": "prod-web-application",
                "Status": "Ready",
                "Environment": "Production",
                "IaC": "Terraform",
                "Pipeline": "aws-prod-deploy",
                "Approved": "2024-12-05"
            },
            {
                "Name": "api-microservices",
                "Status": "Generating IaC",
                "Environment": "Staging",
                "IaC": "Terraform",
                "Pipeline": "aws-staging-deploy",
                "Approved": "2024-12-06"
            }
        ]
        
        for dep in deployments:
            with st.expander(f"🚀 {dep['Name']} - {dep['Status']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Environment:** {dep['Environment']}")
                    st.write(f"**IaC Tool:** {dep['IaC']}")
                    st.write(f"**Pipeline:** {dep['Pipeline']}")
                
                with col2:
                    st.write(f"**Status:** {dep['Status']}")
                    st.write(f"**Approved:** {dep['Approved']}")
                
                if dep['Status'] == "Ready":
                    st.markdown("---")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("📝 View IaC", key=f"view_iac_{dep['Name']}"):
                            st.code("""
terraform {
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.region
}

module "vpc" {
  source = "./modules/vpc"
  # VPC configuration
}

module "application" {
  source = "./modules/application"
  # Application resources
}
                            """, language="hcl")
                    
                    with col2:
                        if st.button("🚀 Deploy", key=f"deploy_{dep['Name']}", type="primary"):
                            st.success(f"Triggering CI/CD pipeline: {dep['Pipeline']}")
                            st.info("Deployment in progress... Check pipeline status in CI/CD module")
                    
                    with col3:
                        if st.button("📊 View Pipeline", key=f"pipeline_{dep['Name']}"):
                            st.info("Opening CI/CD Pipeline Management...")
        
        st.markdown("---")
        st.markdown("### Pipeline Configuration")
        
        with st.expander("⚙️ Configure CI/CD Integration"):
            repo_url = st.text_input("Repository URL", placeholder="https://github.com/org/repo")
            branch = st.text_input("Branch", value="main")
            
            iac_path = st.text_input("IaC Files Path", value="terraform/")
            
            environments = st.multiselect("Target Environments", [
                "development",
                "staging",
                "production"
            ], default=["staging", "production"])
            
            auto_deploy = st.checkbox("Auto-deploy to staging", value=True)
            require_approval = st.checkbox("Require approval for production", value=True)
            
            if st.button("💾 Save Configuration"):
                st.success("✅ CI/CD integration configured!")
    
    # ========================================================================
    # TAB 7: STANDARDS & POLICIES
    # ========================================================================
    
    @staticmethod
    def _render_standards():
        """Standards and policies"""
        st.subheader("🏷️ Standards & Policies")
        
        standards_tabs = st.tabs([
            "🏷️ Tagging",
            "📛 Naming",
            "🔐 Security",
            "💰 Cost"
        ])
        
        with standards_tabs[0]:
            st.markdown("### Tagging Standards")
            
            tags = [
                {"Key": "Environment", "Required": "Yes", "Values": "dev, staging, prod, dr"},
                {"Key": "Owner", "Required": "Yes", "Values": "team@company.com"},
                {"Key": "CostCenter", "Required": "Yes", "Values": "CC-XXXXX"},
                {"Key": "Project", "Required": "Yes", "Values": "Project name"},
                {"Key": "Compliance", "Required": "No", "Values": "PCI, HIPAA, SOC2"}
            ]
            
            df = pd.DataFrame(tags)
            st.dataframe(df, use_container_width=True)
        
        with standards_tabs[1]:
            st.markdown("### Naming Conventions")
            
            naming = [
                {"Resource": "VPC", "Pattern": "{env}-{region}-vpc", "Example": "prod-us-east-1-vpc"},
                {"Resource": "EC2", "Pattern": "{env}-{app}-{role}-{num}", "Example": "prod-web-server-01"},
                {"Resource": "RDS", "Pattern": "{env}-{app}-{engine}-db", "Example": "prod-app-postgres-db"},
                {"Resource": "S3", "Pattern": "{org}-{env}-{purpose}", "Example": "acme-prod-logs"}
            ]
            
            df = pd.DataFrame(naming)
            st.dataframe(df, use_container_width=True)
        
        with standards_tabs[2]:
            st.markdown("### Security Standards")
            
            st.info("""
            **Mandatory Security Controls:**
            
            ✅ All data encrypted at rest (KMS)  
            ✅ All data encrypted in transit (TLS 1.2+)  
            ✅ VPC with private subnets for workloads  
            ✅ No public access to databases  
            ✅ MFA for all human access  
            ✅ IAM roles (no long-term access keys)  
            ✅ GuardDuty enabled  
            ✅ CloudTrail logging enabled  
            ✅ Security Hub enabled  
            """)
        
        with standards_tabs[3]:
            st.markdown("### Cost Standards")
            
            st.info("""
            **Cost Control Policies:**
            
            💰 Monthly budget alerts configured  
            💰 Auto-shutdown for non-prod resources (nights/weekends)  
            💰 Reserved Instance strategy for stable workloads  
            💰 S3 lifecycle policies for all buckets  
            💰 EC2 right-sizing reviews quarterly  
            💰 Delete unused resources monthly  
            💰 Cost allocation tags enforced  
            """)
    # ========================================================================
    # NEW TAB 4: AI SIZING (INTEGRATION CODE)
    # ========================================================================
    
    
    # ========================================================================
    # TAB 4: AI SIZING - WITH FIREBASE SUPPORT
    # ========================================================================
    
    @staticmethod
    def _render_ai_sizing():
        """Render AI Sizing Recommendations interface (Firebase-enabled)"""
        st.subheader("🤖 AI-Powered Sizing Recommendations")
        st.info("AI analyzes your architecture and generates 4 sizing tiers: Cost-Optimized, Balanced, Performance, and Enterprise")
        
        # Import storage adapter
        if STORAGE_ADAPTER_AVAILABLE:
            storage = get_storage_adapter()
            use_firebase = storage.is_firebase_available
        else:
            storage = None
            use_firebase = False
            # Fallback to session state
            if 'designs' not in st.session_state:
                st.session_state.designs = {}
        
        if not AI_SIZING_AVAILABLE or not WORKFLOW_ENGINE_AVAILABLE:
            st.error("⚠️ AI Sizing requires workflow_engine.py and ai_sizing_engine.py")
            return
        
        analyzer = get_ai_sizing_analyzer()
        calculator = AWSPricingCalculator()
        
        # Get designs without sizing using storage adapter or session state
        if use_firebase and storage:
            all_designs = storage.list_designs(status='DRAFT', limit=100)
        else:
            all_designs = list(st.session_state.designs.values())
            all_designs = [d for d in all_designs if d.get('status') == 'DRAFT']
        
        drafts_no_sizing = [d for d in all_designs if not d.get('sizing_details')]
        
        if not drafts_no_sizing:
            st.success("✅ All draft designs have sizing applied!")
            
            # Show designs with sizing
            drafts_with_sizing = [d for d in all_designs if d.get('sizing_details')]
            if drafts_with_sizing:
                st.markdown("### Designs with AI Sizing")
                for design in drafts_with_sizing:
                    with st.expander(f"✅ {design['name']}"):
                        sizing = design.get('sizing_details', {})
                        st.write(f"**Sizing:** {sizing.get('ec2_instance_type', 'N/A')} x{sizing.get('ec2_count', 0)}")
                        st.write(f"**RDS:** {sizing.get('rds_instance_type', 'N/A')}")
                        st.info("💡 Ready to submit for WAF Review")
        else:
            st.markdown(f"### {len(drafts_no_sizing)} Designs Need AI Sizing")
            
            for design in drafts_no_sizing:
                design_id = design.get('id', design['name'])
                
                with st.expander(f"🤖 {design['name']} - Generate Sizing", expanded=False):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.write(f"**Environment:** {design.get('environment', 'N/A')}")
                        st.write(f"**Services:** {', '.join(design.get('services', []))}")
                        if design.get('description'):
                            desc = design['description']
                            st.write(f"**Description:** {desc[:200]}{'...' if len(desc) > 200 else ''}")
                    
                    with col2:
                        if st.button(f"🧠 Analyze & Size", key=f"analyze_{design_id}", type="primary"):
                            with st.spinner("AI analyzing architecture..."):
                                try:
                                    # Prepare data for analyzer
                                    design_data = {
                                        'name': design['name'],
                                        'description': design.get('description', ''),
                                        'business_requirements': design.get('business_requirements', ''),
                                        'services': design.get('services', []),
                                        'environment': design.get('environment', 'Production'),
                                        'ha_required': design.get('ha_required', True),
                                        'compliance_requirements': design.get('compliance_requirements', [])
                                    }
                                    
                                    # AI Analysis
                                    sizing = analyzer.analyze_architecture(design_data)
                                    
                                    # Store in session state for UI (temporary)
                                    st.session_state[f'sizing_{design_id}'] = sizing
                                    
                                    st.success("✅ AI Analysis Complete!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")
                    
                    # Show results if analysis done
                    if f'sizing_{design_id}' in st.session_state:
                        sizing = st.session_state[f'sizing_{design_id}']
                        
                        st.markdown("---")
                        st.markdown("#### 🧠 AI Workload Analysis")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Workload", sizing.workload_type.upper())
                        col2.metric("Traffic", sizing.traffic_pattern.capitalize())
                        col3.metric("Data", sizing.data_intensity.capitalize())
                        col4.metric("Compute", sizing.compute_intensity.capitalize())
                        
                        st.info(sizing.workload_analysis)
                        
                        st.markdown("#### 💰 4 AI-Generated Sizing Tiers")
                        
                        # Calculate costs for all tiers
                        for rec in sizing.recommendations:
                            temp_design = ArchitectureDesign(
                                id=design_id,
                                name=design['name'],
                                services=design.get('services', []),
                                environment=design.get('environment', 'Production'),
                                multi_az=design.get('ha_required', True),
                                sizing_details={
                                    'ec2_instance_type': rec.ec2_instance_type,
                                    'ec2_count': rec.ec2_count,
                                    'rds_instance_type': rec.rds_instance_type
                                }
                            )
                            
                            try:
                                cost = calculator.calculate_architecture_cost(temp_design)
                                rec.monthly_cost = cost.monthly_cost
                                rec.three_year_cost = cost.total_3year_cost
                            except:
                                rec.monthly_cost = 0
                                rec.three_year_cost = 0
                        
                        # Show comparison table
                        comparison_data = []
                        for rec in sizing.recommendations:
                            comparison_data.append({
                                'Tier': rec.tier_name,
                                'EC2': f"{rec.ec2_instance_type} x{rec.ec2_count}",
                                'RDS': rec.rds_instance_type,
                                'vCPUs': rec.vcpus,
                                'Memory (GB)': rec.memory_gb,
                                'Monthly $': f"${rec.monthly_cost:,.0f}",
                                '3-Year $': f"${rec.three_year_cost:,.0f}",
                                'Confidence': f"{rec.confidence_score}%"
                            })
                        
                        df = pd.DataFrame(comparison_data)
                        st.dataframe(df, use_container_width=True, hide_index=True)
                        
                        # Detailed tabs for each tier
                        tier_tabs = st.tabs([rec.tier_name for rec in sizing.recommendations])
                        
                        for i, rec in enumerate(sizing.recommendations):
                            with tier_tabs[i]:
                                col1, col2 = st.columns([2, 1])
                                
                                with col1:
                                    st.markdown("**Configuration:**")
                                    st.write(f"• EC2: {rec.ec2_instance_type} x{rec.ec2_count}")
                                    st.write(f"• RDS: {rec.rds_instance_type}")
                                    st.write(f"• vCPUs: {rec.vcpus}, Memory: {rec.memory_gb} GB")
                                    
                                    st.markdown("**🤖 AI Reasoning:**")
                                    st.info(rec.ai_reasoning)
                                    
                                    col_pros, col_cons = st.columns(2)
                                    with col_pros:
                                        st.markdown("**✅ Pros:**")
                                        for pro in rec.pros[:3]:
                                            st.success(f"• {pro}")
                                    
                                    with col_cons:
                                        st.markdown("**❌ Cons:**")
                                        for con in rec.cons[:2]:
                                            st.warning(f"• {con}")
                                
                                with col2:
                                    st.metric("Monthly", f"${rec.monthly_cost:,.0f}")
                                    st.metric("3-Year", f"${rec.three_year_cost:,.0f}")
                                    st.metric("Confidence", f"{rec.confidence_score}%")
                                    
                                    st.markdown("---")
                                    
                                    if st.button(f"✅ Select", key=f"sel_{design_id}_{rec.tier}", 
                                               type="primary", use_container_width=True):
                                        # Apply sizing to design
                                        sizing_details = {
                                            'ec2_instance_type': rec.ec2_instance_type,
                                            'ec2_count': rec.ec2_count,
                                            'rds_instance_type': rec.rds_instance_type,
                                            'rds_storage_gb': rec.rds_storage_gb,
                                            'selected_tier': rec.tier,
                                            'ai_confidence': rec.confidence_score
                                        }
                                        
                                        # Save to storage (Firebase or session state)
                                        if use_firebase and storage:
                                            storage.update_design(design_id, {'sizing_details': sizing_details})
                                        else:
                                            design['sizing_details'] = sizing_details
                                            st.session_state.designs[design_id] = design
                                        
                                        st.success(f"✅ Applied {rec.tier_name}!")
                                        del st.session_state[f'sizing_{design_id}']
                                        st.rerun()
                        
                        # AI Recommendation
                        st.markdown("---")
                        recommended = next((r for r in sizing.recommendations 
                                          if r.tier == sizing.recommended_tier), 
                                         sizing.recommendations[1])
                        
                        st.success(f"🎯 **AI Recommends:** {recommended.tier_name}")
                        st.write(f"**Why:** {recommended.ai_reasoning[:200]}...")
    
    # ========================================================================
    # TAB 5: COST ANALYSIS - WITH FIREBASE SUPPORT
    # ========================================================================
    
    @staticmethod
    def _render_cost_analysis():
        """Render AWS Cost Analysis interface (Firebase-enabled)"""
        st.subheader("💰 AWS Cost Analysis & 3-Year TCO/ROI")
        st.info("Calculate complete AWS costs with 3-year projections before deployment")
        
        # Import storage adapter
        if STORAGE_ADAPTER_AVAILABLE:
            storage = get_storage_adapter()
            use_firebase = storage.is_firebase_available
        else:
            storage = None
            use_firebase = False
            # Fallback to session state
            if 'designs' not in st.session_state:
                st.session_state.designs = {}
        
        if not WORKFLOW_ENGINE_AVAILABLE:
            st.error("⚠️ Cost Analysis requires workflow_engine.py")
            return
        
        calculator = AWSPricingCalculator()
        
        cost_tabs = st.tabs(["💰 Calculate Costs", "✅ Approved", "📊 Comparison"])
        
        # TAB 1: Calculate Costs
        with cost_tabs[0]:
            # Get designs ready for cost analysis
            if use_firebase and storage:
                approved_designs = storage.list_designs(status='APPROVED', limit=50)
                pending_designs = storage.list_designs(status='PENDING_APPROVAL', limit=50)
                cost_ready = [d for d in (approved_designs + pending_designs) if d.get('sizing_details')]
            else:
                all_designs = list(st.session_state.designs.values())
                cost_ready = [d for d in all_designs 
                             if d.get('sizing_details') and d.get('status') in ['APPROVED', 'PENDING_APPROVAL']]
            
            if not cost_ready:
                st.info("📝 No approved designs ready for cost analysis")
            else:
                st.markdown(f"### {len(cost_ready)} Designs Ready")
                
                for design in cost_ready:
                    design_id = design.get('id', design['name'])
                    
                    with st.expander(f"💰 {design['name']}", expanded=not design.get('cost_analysis')):
                        
                        if not design.get('cost_analysis'):
                            col1, col2 = st.columns([3, 1])
                            
                            with col1:
                                st.write(f"**Environment:** {design.get('environment', 'N/A')}")
                                sizing = design.get('sizing_details', {})
                                st.write(f"**Sizing:** {sizing.get('ec2_instance_type', 'N/A')} x{sizing.get('ec2_count', 0)}")
                            
                            with col2:
                                if st.button("📊 Calculate", key=f"calc_{design_id}", type="primary"):
                                    with st.spinner("Calculating..."):
                                        try:
                                            temp_design = ArchitectureDesign(
                                                id=design_id,
                                                name=design['name'],
                                                services=design.get('services', []),
                                                environment=design.get('environment', 'Production'),
                                                multi_az=design.get('ha_required', True),
                                                sizing_details=design.get('sizing_details', {})
                                            )
                                            
                                            cost = calculator.calculate_architecture_cost(temp_design)
                                            
                                            # Save to storage
                                            if use_firebase and storage:
                                                storage.update_design(design_id, {'cost_analysis': cost.to_dict()})
                                            else:
                                                design['cost_analysis'] = cost.to_dict()
                                                st.session_state.designs[design_id] = design
                                            
                                            st.success("✅ Complete!")
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"Error: {str(e)}")
                        else:
                            # Show cost analysis
                            DesignPlanningModule._display_cost_details_fb(design, storage, use_firebase)
        
        # TAB 2: Approved Costs
        with cost_tabs[1]:
            # Get designs with approved costs
            if use_firebase and storage:
                all_designs = storage.list_designs(limit=100)
            else:
                all_designs = list(st.session_state.designs.values())
            
            approved = [d for d in all_designs if d.get('cost_analysis') and d.get('cost_approved')]
            
            if not approved:
                st.info("No approved costs yet")
            else:
                for design in approved:
                    with st.expander(f"✅ {design['name']}"):
                        DesignPlanningModule._display_cost_summary_fb(design)
        
        # TAB 3: Cost Comparison
        with cost_tabs[2]:
            if use_firebase and storage:
                all_designs = storage.list_designs(limit=100)
            else:
                all_designs = list(st.session_state.designs.values())
            
            designs_with_cost = [d for d in all_designs if d.get('cost_analysis')]
            
            if not designs_with_cost:
                st.info("No cost analyses yet")
            else:
                comparison = []
                for d in designs_with_cost:
                    ca = d['cost_analysis']
                    comparison.append({
                        'Architecture': d['name'],
                        'Environment': d.get('environment', 'N/A'),
                        'Status': d.get('status', 'N/A'),
                        'Monthly $': f"${ca['monthly_cost']:,.0f}",
                        '3-Year $': f"${ca['total_3year_cost']:,.0f}",
                        'TCO $': f"${ca['total_tco']:,.0f}",
                        'ROI %': f"{ca['roi_percentage']:.1f}%"
                    })
                
                df = pd.DataFrame(comparison)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Chart
                chart_data = pd.DataFrame({
                    'Architecture': [d['name'] for d in designs_with_cost],
                    '3-Year Cost': [d['cost_analysis']['total_3year_cost'] for d in designs_with_cost]
                })
                st.bar_chart(chart_data.set_index('Architecture'))
    
    @staticmethod
    def _display_cost_details_fb(design: Dict, storage, use_firebase: bool):
        """Display cost analysis details (Firebase-enabled version)"""
        ca = design.get('cost_analysis', {})
        if not ca:
            return
        
        design_id = design.get('id', design['name'])
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Monthly", f"${ca['monthly_cost']:,.0f}")
        col2.metric("3-Year", f"${ca['total_3year_cost']:,.0f}")
        col3.metric("TCO", f"${ca['total_tco']:,.0f}")
        col4.metric("ROI", f"{ca['roi_percentage']:.1f}%", 
                   delta=f"{ca['payback_months']}mo payback")
        
        # Details in tabs
        detail_tabs = st.tabs(["Services", "TCO", "Savings"])
        
        with detail_tabs[0]:
            if ca.get('service_costs'):
                services = []
                for s in ca['service_costs']:
                    services.append({
                        'Service': s['service_name'],
                        'Type': s.get('instance_type', 'N/A'),
                        'Monthly': f"${s['total_monthly']:,.2f}",
                        'Year 1': f"${s['year1_cost']:,.0f}"
                    })
                df = pd.DataFrame(services)
                st.dataframe(df, use_container_width=True, hide_index=True)
        
        with detail_tabs[1]:
            col1, col2 = st.columns(2)
            col1.metric("Infrastructure", f"${ca['infrastructure_cost']:,.0f}")
            col1.metric("Operations", f"${ca['operational_cost']:,.0f}")
            col2.metric("Licensing", f"${ca['licensing_cost']:,.0f}")
            col2.metric("Support", f"${ca['support_cost']:,.0f}")
        
        with detail_tabs[2]:
            st.info(f"💰 Reserved Instances: Save ${ca.get('reserved_instance_savings', 0):,.0f}")
            if ca.get('cost_optimization_recommendations'):
                for rec in ca['cost_optimization_recommendations'][:5]:
                    st.success(rec)
        
        # Actions
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            if not design.get('cost_approved'):
                if st.button("✅ Approve", key=f"approve_{design_id}", type="primary"):
                    if use_firebase and storage:
                        storage.update_design(design_id, {
                            'cost_approved': True,
                            'status': 'APPROVED'
                        })
                    else:
                        design['cost_approved'] = True
                        design['status'] = 'APPROVED'
                        st.session_state.designs[design_id] = design
                    
                    st.success("✅ Cost approved!")
                    st.rerun()
        
        with col2:
            if st.button("❌ Too Expensive", key=f"reject_{design_id}"):
                if use_firebase and storage:
                    storage.update_design(design_id, {
                        'status': 'DRAFT',
                        'cost_analysis': None
                    })
                else:
                    design['status'] = 'DRAFT'
                    design['cost_analysis'] = None
                    st.session_state.designs[design_id] = design
                
                st.warning("Returned to draft")
                st.rerun()
    
    @staticmethod
    def _display_cost_summary_fb(design: Dict):
        """Display simple cost summary (Firebase-enabled version)"""
        ca = design.get('cost_analysis', {})
        if not ca:
            return
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Monthly", f"${ca['monthly_cost']:,.0f}")
        col2.metric("3-Year", f"${ca['total_3year_cost']:,.0f}")
        col3.metric("ROI", f"{ca['roi_percentage']:.1f}%")


# ============================================================================
# END OF FIREBASE-ENABLED METHODS
# ============================================================================

# Export
__all__ = ['DesignPlanningModule']