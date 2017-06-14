package eidassaml.starterkit.person_attributes.legal_persons_attributes;

import eidassaml.starterkit.EidasAttribute;
import eidassaml.starterkit.EidasLegalPersonAttributes;
import eidassaml.starterkit.Utils;
import eidassaml.starterkit.person_attributes.AbstractNonLatinScriptAttribute;
import eidassaml.starterkit.person_attributes.EidasPersonAttributes;

/**
 * Created by yuri on 2/12/2016.
 */
public class LegalNameAttribute extends AbstractNonLatinScriptAttribute {
	
    public LegalNameAttribute(String value) {
        super(value);
    }
    public LegalNameAttribute(){}
    
    public LegalNameAttribute(String latinScript, String nonLatinScript) {
		super(latinScript, nonLatinScript);
	}

    @Override
	public String getTemplateName() {
		return Utils.IsNullOrEmpty(this.getNonLatinScript()) ? "legalname" : "legalname_transliterated";
	}

    @Override
    public String type() {
        return EidasAttribute.TYPE_LegalName;
    }
    
    @Override
	public String toString() {
		return type() + " " + this.getLatinScript();
	}

    @Override
    public EidasPersonAttributes getPersonAttributeType() {
        return EidasLegalPersonAttributes.LegalName;
    }
}
