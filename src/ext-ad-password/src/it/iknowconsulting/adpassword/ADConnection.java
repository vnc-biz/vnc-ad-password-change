/*
   Copyright 2012 Antonio Messina (a.messina@iknowconsulting.it)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Based on ADConnection
// A Java class that encapsulates a JNDI connection to an Active Directory
// Written by Jeremy E. Mortis  mortis@ucalgary.ca  2002-07-03
//
// References:
// http://homepages.ucalgary.ca/~mortis/software/ADConnection.txt
// http://ldapwiki.willeke.com/wiki/Example%20-%20Active%20Directory%20Change%20Password%20JNDI

package it.iknowconsulting.adpassword;

import com.zimbra.cs.account.Domain;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Properties;
import java.io.UnsupportedEncodingException;

public class ADConnection {

	DirContext ldapContext;
	//LdapContext ldapContext;
	String authLdapSearchBase;
	String authLdapSearchFilter;

	public ADConnection(Domain domain) throws NamingException {
		System.out.println("[ADConnection] Domain :"+domain);

		String authLdapURL = domain.getAuthLdapURL()[0];
		String authLdapSearchBindDn = domain.getAuthLdapSearchBindDn();
		String authLdapSearchBindPassword = domain.getAuthLdapSearchBindPassword();
		authLdapSearchBase = domain.getAuthLdapSearchBase();
		authLdapSearchFilter = domain.getAuthLdapSearchFilter();

		System.out.println("[ADConnection] authLdapURL :"+ authLdapURL);
		System.out.println("[ADConnection] authLdapSearchBindDn :"+ authLdapSearchBindDn);
		System.out.println("[ADConnection] authLdapSearchBindPassword :"+ authLdapSearchBindPassword);
		System.out.println("[ADConnection] zimbraAuthLdapBindDn :"+ domain.getAuthLdapBindDn());
		System.out.println("[ADConnection] zimbraAuthLdapSearchBindDn :"+ domain.getAuthLdapSearchBindDn());
		System.out.println("[ADConnection] zimbraAuthLdapSearchBase :"+ authLdapSearchBase);

		System.out.println("[ADConnection] zimbraAuthLdapSearchFilter :"+ domain.getAuthLdapSearchFilter());

		Hashtable ldapEnv = new Hashtable(11);
		//Properties ldapEnv = new Properties();
		ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		ldapEnv.put(Context.PROVIDER_URL, authLdapURL);
		ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
		ldapEnv.put(Context.SECURITY_PRINCIPAL, authLdapSearchBindDn);
		ldapEnv.put(Context.SECURITY_CREDENTIALS, authLdapSearchBindPassword);
		ldapEnv.put(Context.SECURITY_PROTOCOL, "ssl");
		ldapEnv.put("com.sun.jndi.ldap.read.timeout", "10000");
		ldapContext = new InitialDirContext(ldapEnv);
		//ldapContext = new InitialLdapContext(ldapEnv,null);
	}

	public void updatePassword(String username, String password) throws NamingException {
		String quotedPassword = "\"" + password + "\"";
		
		try{
			final byte pwdArray[] = quotedPassword.getBytes("UTF-16LE");
			

		/*char unicodePwd[] = quotedPassword.toCharArray();
		System.out.println("[ADConnection] updatePassword username:"+username+"  Password: "+password);
		byte pwdArray[] = new byte[unicodePwd.length * 2];
		for (int i=0; i<unicodePwd.length; i++) {
			pwdArray[i*2 + 1] = (byte) (unicodePwd[i] >>> 8);
			pwdArray[i*2 + 0] = (byte) (unicodePwd[i] & 0xff);
		}*/
			NamingEnumeration cninfo = get(username);
			String cnValue = null;
			while(cninfo.hasMore())
			{
				Attributes attrs = ((SearchResult)cninfo.next()).getAttributes();			
				if(attrs.get("distinguishedName") != null)
				{
					String[] cnPair = attrs.get("distinguishedName").toString().split(":");
					cnValue = cnPair[1].trim();
					System.out.println("cn user value=========="+cnValue);
				}	
			}
			ModificationItem[] mods = new ModificationItem[1];
			mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("unicodePwd", pwdArray));
			ldapContext.modifyAttributes(cnValue, mods);
		
			ldapContext.close();
		}catch(UnsupportedEncodingException ex)
                {
                        ex.printStackTrace();
                }
		

    	}
	
	NamingEnumeration get(String searchFilter) throws NamingException {
	
		NamingEnumeration results= null;
	try{	
		System.out.println("[ADConnection] get method searchFilter : "+searchFilter);
		//String[] returnedAttrs = { "distinguishedName","cn","givenname","mail","sAMAccountName","dc","ou","name","dn"};
		String[] returnedAttrs = { "distinguishedName","cn"};
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setReturningAttributes(returnedAttrs);
		//NamingEnumeration results = ldapContext.search(authLdapSearchBase, searchFilter, searchControls);
		 results = ldapContext.search(authLdapSearchBase, "sAMAccountName="+searchFilter, searchControls);

		 /*if (results.hasMore()) {
                	Attributes attrs = ((SearchResult) results.next()).getAttributes();
			System.out.println("distinguishedName====>"+ attrs.get("distinguishedName"));
                	System.out.println("givenName====>"+ attrs.get("givenName"));
	                System.out.println("name=====>"+ attrs.get("name"));
        	        System.out.println("cn======> "+ attrs.get("cn"));
                	System.out.println("sAMAccountName====>"+ attrs.get("sAMAccountName"));
	                System.out.println("mail======>"+ attrs.get("mail"));
			System.out.println("dc======>"+ attrs.get("dc"));
			System.out.println("ou======>"+ attrs.get("ou"));
			System.out.println("dn======>"+ attrs.get("dn"));

			//return results;
        	    }else{
                	//throw new Exception("Invalid User");
			System.out.println("Error");
        	    }*/	
		}catch( NamingException ex)
		{
			ex.printStackTrace();
		}

		return results;
	}

	public NamingEnumeration getUsers() throws NamingException {
		System.out.println("[ADConnection] getUsers");
		String searchFilter = "(userPrincipalName=*)";
		return get(searchFilter);
	}

	public NamingEnumeration fetchUser(String uid) throws NamingException {
		System.out.println("[ADConnection] fetchUser uid: "+uid);
		String searchFilter = "(sAMAccountName="+uid+")";
		return get(searchFilter);
	}
	}
