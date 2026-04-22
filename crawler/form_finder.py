"""
ScriptX Form Finder
Discovers and analyzes HTML forms for XSS testing
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re


@dataclass
class FormInput:
    """Represents a form input field"""
    name: str
    input_type: str  # text, hidden, password, etc.
    tag: str  # input, textarea, select
    id: Optional[str] = None
    value: Optional[str] = None
    placeholder: Optional[str] = None
    required: bool = False
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    options: List[str] = field(default_factory=list)  # For select elements
    
    def is_injectable(self) -> bool:
        """Check if this input can be used for XSS injection"""
        # Skip certain input types
        non_injectable = ['submit', 'button', 'image', 'reset', 'file']
        return self.input_type.lower() not in non_injectable


@dataclass 
class Form:
    """Represents an HTML form"""
    action: str
    method: str
    page_url: str
    enctype: str = 'application/x-www-form-urlencoded'
    id: Optional[str] = None
    name: Optional[str] = None
    inputs: List[FormInput] = field(default_factory=list)
    selector: Optional[str] = None  # CSS selector to identify form
    has_captcha: bool = False  # Whether this form's page has a CAPTCHA
    
    def get_injectable_inputs(self) -> List[FormInput]:
        """Get inputs that can be used for XSS testing"""
        return [inp for inp in self.inputs if inp.is_injectable()]
    
    def get_absolute_action(self) -> str:
        """Get absolute URL for form action"""
        if self.action.startswith(('http://', 'https://')):
            return self.action
        return urljoin(self.page_url, self.action)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'action': self.action,
            'absolute_action': self.get_absolute_action(),
            'method': self.method,
            'enctype': self.enctype,
            'id': self.id,
            'name': self.name,
            'inputs': [
                {
                    'name': inp.name,
                    'type': inp.input_type,
                    'tag': inp.tag,
                    'injectable': inp.is_injectable()
                }
                for inp in self.inputs
            ]
        }


class FormFinder:
    """
    Discovers and analyzes HTML forms.
    Identifies injectable inputs for XSS testing.
    """
    
    def __init__(self):
        self.forms_found: List[Form] = []
        
    def find_forms(self, html_content: str, page_url: str) -> List[Form]:
        """
        Find all forms in HTML content.
        
        Args:
            html_content: HTML page content
            page_url: URL of the page
            
        Returns:
            List of Form objects
        """
        forms = []
        soup = BeautifulSoup(html_content, 'lxml')
        
        for idx, form_tag in enumerate(soup.find_all('form')):
            form = self._parse_form(form_tag, page_url, idx)
            if form.inputs:  # Only include forms with inputs
                forms.append(form)
                self.forms_found.append(form)
        
        return forms
    
    def _parse_form(self, form_tag, page_url: str, index: int) -> Form:
        """Parse a form element"""
        
        # Get form attributes
        action = form_tag.get('action', '') or page_url
        method = (form_tag.get('method', 'GET') or 'GET').upper()
        enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
        form_id = form_tag.get('id')
        form_name = form_tag.get('name')
        
        # Generate CSS selector
        if form_id:
            selector = f'#{form_id}'
        elif form_name:
            selector = f'form[name="{form_name}"]'
        else:
            selector = f'form:nth-of-type({index + 1})'
        
        # Parse inputs
        inputs = []
        
        # Input elements
        for input_tag in form_tag.find_all('input'):
            input_obj = self._parse_input(input_tag)
            if input_obj:
                inputs.append(input_obj)
        
        # Textarea elements
        for textarea in form_tag.find_all('textarea'):
            input_obj = self._parse_textarea(textarea)
            if input_obj:
                inputs.append(input_obj)
        
        # Select elements
        for select in form_tag.find_all('select'):
            input_obj = self._parse_select(select)
            if input_obj:
                inputs.append(input_obj)
        
        return Form(
            action=action,
            method=method,
            page_url=page_url,
            enctype=enctype,
            id=form_id,
            name=form_name,
            inputs=inputs,
            selector=selector
        )
    
    def _parse_input(self, input_tag) -> Optional[FormInput]:
        """Parse an input element"""
        name = input_tag.get('name')
        if not name:
            return None
        
        return FormInput(
            name=name,
            input_type=input_tag.get('type', 'text'),
            tag='input',
            id=input_tag.get('id'),
            value=input_tag.get('value', ''),
            placeholder=input_tag.get('placeholder'),
            required=input_tag.has_attr('required'),
            max_length=self._parse_int(input_tag.get('maxlength')),
            pattern=input_tag.get('pattern')
        )
    
    def _parse_textarea(self, textarea) -> Optional[FormInput]:
        """Parse a textarea element"""
        name = textarea.get('name')
        if not name:
            return None
        
        return FormInput(
            name=name,
            input_type='textarea',
            tag='textarea',
            id=textarea.get('id'),
            value=textarea.string or '',
            placeholder=textarea.get('placeholder'),
            required=textarea.has_attr('required'),
            max_length=self._parse_int(textarea.get('maxlength'))
        )
    
    def _parse_select(self, select) -> Optional[FormInput]:
        """Parse a select element"""
        name = select.get('name')
        if not name:
            return None
        
        options = []
        for option in select.find_all('option'):
            value = option.get('value', option.string or '')
            options.append(value)
        
        return FormInput(
            name=name,
            input_type='select',
            tag='select',
            id=select.get('id'),
            required=select.has_attr('required'),
            options=options
        )
    
    def _parse_int(self, value) -> Optional[int]:
        """Safely parse integer"""
        try:
            return int(value) if value else None
        except:
            return None
    
    def get_all_injectable_params(self) -> List[Dict[str, Any]]:
        """Get all injectable parameters from all forms"""
        params = []
        
        for form in self.forms_found:
            for inp in form.get_injectable_inputs():
                params.append({
                    'name': inp.name,
                    'type': inp.input_type,
                    'form_action': form.get_absolute_action(),
                    'form_method': form.method,
                    'form_selector': form.selector
                })
        
        return params
    
    def get_stats(self) -> Dict[str, int]:
        """Get form discovery statistics"""
        total_inputs = sum(len(f.inputs) for f in self.forms_found)
        injectable = sum(len(f.get_injectable_inputs()) for f in self.forms_found)
        
        return {
            'forms': len(self.forms_found),
            'total_inputs': total_inputs,
            'injectable_inputs': injectable
        }
