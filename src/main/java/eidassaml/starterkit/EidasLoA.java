/* 
 * 
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * 
 * Date: 09 Feb 2016
 * Authors: Governikus GmbH & Co. KG
 * 
*/
package eidassaml.starterkit;

/**
 * 
 * 
 * @author hohnholt
 *
 */
public enum EidasLoA {
	
	/**
	 * http://eidas.europa.eu/LoA/low
	 */
	Low("http://eidas.europa.eu/LoA/low"),
	
	/**
	 * http://eidas.europa.eu/LoA/substantial
	 */
	Substantial("http://eidas.europa.eu/LoA/substantial"),
	
	/**
	 * http://eidas.europa.eu/LoA/high
	 */
	High("http://eidas.europa.eu/LoA/high");

	public final String NAME;
	
	private EidasLoA(String name)
	{
		NAME = name;
	}
	
	public static EidasLoA GetValueOf(String s) throws ErrorCodeException
	{
		if(Low.NAME.equals(s)){
			return Low;
		}
				
		else if(Substantial.NAME.equals(s)){
			return Substantial;
		}
		
		else if(High.NAME.equals(s)){
			return High;
		}
		else {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported loa value:" + s);
		}
	}
	
}
