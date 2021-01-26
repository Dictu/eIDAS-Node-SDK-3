package eidassaml.starterkit.person_attributes.natural_persons_attribute;

import eidassaml.starterkit.EidasAttribute;
import eidassaml.starterkit.EidasNaturalPersonAttributes;
import eidassaml.starterkit.Utils;
import eidassaml.starterkit.person_attributes.AbstractNonLatinScriptAttribute;
import eidassaml.starterkit.person_attributes.EidasPersonAttributes;

public class AdditionalNaturalPersonAttribute extends AbstractNonLatinScriptAttribute {

    public AdditionalNaturalPersonAttribute(){}
    public AdditionalNaturalPersonAttribute(String value) {
        super(value);
    }

    @Override
    public String getTemplateName() {
        return Utils.IsNullOrEmpty(this.getNonLatinScript()) ? "additionalnaturalpersonattribute" : "additionalnaturalpersonattribute_transliterated";
    }

    public AdditionalNaturalPersonAttribute(String value, String transliteratedValue) {
        super(value,transliteratedValue);
    }

    @Override
    public String type() {
        return EidasAttribute.TYPE_AdditionalAttribute;
    }

    @Override
    public String toString() {
        return type() + " " + this.getLatinScript();
    }

    @Override
    public EidasPersonAttributes getPersonAttributeType() {
        return EidasNaturalPersonAttributes.AdditionalAttribute;
    }
}
