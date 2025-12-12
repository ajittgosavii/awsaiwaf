"""
Compliance Module - Wrapper for compliance_module.py
"""

import streamlit as st

class ComplianceModule:
    """Wrapper class for compliance module"""
    
    @staticmethod
    def render():
        """Render compliance module"""
        st.subheader("🔒 Compliance Frameworks")
        
        st.info("""
        Compliance framework assessment for:
        - PCI-DSS
        - HIPAA
        - SOC 2
        - ISO 27001
        """)
        
        st.warning("⚠️ Module under development. Full compliance checking coming soon!")
