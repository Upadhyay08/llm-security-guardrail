import re
import spacy
import streamlit as st
from typing import Tuple, List, Dict

@st.cache_resource
def load_spacy_model():
    """Dynamically downloads and caches the spaCy model on Streamlit Cloud."""
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        from spacy.cli import download
        download("en_core_web_sm")
        return spacy.load("en_core_web_sm")
    except Exception as e:
        st.error(f"Failed to load spaCy model: {e}")
        return None

# Load model via Streamlit cached function
nlp = load_spacy_model()
