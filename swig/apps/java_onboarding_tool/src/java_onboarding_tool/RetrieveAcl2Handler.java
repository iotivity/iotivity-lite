package java_onboarding_tool;

import org.iotivity.OCAceConnectionType;
import org.iotivity.OCAcePermissionsMask;
import org.iotivity.OCAceResource;
import org.iotivity.OCAceSubjectType;
import org.iotivity.OCObt;
import org.iotivity.OCObtAclHandler;
import org.iotivity.OCSecurityAce;
import org.iotivity.OCSecurityAcl;
import org.iotivity.OCUuidUtil;

public class RetrieveAcl2Handler implements OCObtAclHandler {

    @Override
    public void handler(OCSecurityAcl acl) {
        if (acl != null) {
            System.out.println("\n/oic/sec/acl2:");
            OCSecurityAce ac = acl.getSubjectsListHead();
            System.out.println("\n################################################");
            if (ac == null) {
                System.out.println("No security ACEs found.");
            }
            while (ac != null) {
                System.out.println("aceid: " + ac.getAceid());
                if (ac.getSubjectType() == OCAceSubjectType.OC_SUBJECT_UUID) {
                    System.out.println("subject: " + OCUuidUtil.uuidToString(ac.getSubject().getUuid()));
                } else if (ac.getSubjectType() == OCAceSubjectType.OC_SUBJECT_ROLE) {
                    System.out.println("Roleid_role: " + ac.getSubject().getRole());
                if (ac.getSubject().getAuthority() != null && !ac.getSubject().getAuthority().isEmpty()) {
                    System.out.println("Roleid_authority: " + ac.getSubject().getAuthority());
                }
              } else if (ac.getSubjectType() == OCAceSubjectType.OC_SUBJECT_CONN) {
                  System.out.print("connection type: ");
                if (ac.getSubject().getConn() == OCAceConnectionType.OC_CONN_AUTH_CRYPT) {
                    System.out.println("auth-crypt");
                } else {
                    System.out.println("anon-clear");
                }
              }
              StringBuilder permissions = new StringBuilder();
              permissions.append("Permissions:");
              if ((ac.getPermission() & OCAcePermissionsMask.CREATE) == OCAcePermissionsMask.CREATE) {
                  permissions.append(" C");
              }
              if ((ac.getPermission() & OCAcePermissionsMask.RETRIEVE) == OCAcePermissionsMask.RETRIEVE) {
                  permissions.append(" R");
              }
              if ((ac.getPermission() & OCAcePermissionsMask.UPDATE) == OCAcePermissionsMask.UPDATE) {
                  permissions.append(" U");
              }
              if ((ac.getPermission() & OCAcePermissionsMask.DELETE) == OCAcePermissionsMask.DELETE) {
                  permissions.append(" D");
              }
              if ((ac.getPermission() & OCAcePermissionsMask.NOTIFY) == OCAcePermissionsMask.NOTIFY) {
                  permissions.append(" N");
              }
              System.out.println(permissions);
              StringBuilder aceResources = new StringBuilder();
              aceResources.append("Resources: ");
              OCAceResource res = ac.getResourcesListHead();
              while (res != null) {
                if (res.getHref() != null && !res.getHref().isEmpty()) {
                    aceResources.append(" " + res.getHref() + " ");
                } else if (res.getWildcard() != null) {
                  switch (res.getWildcard()) {
                  case OC_ACE_WC_ALL:
                      aceResources.append(" *");
                    break;
                  case OC_ACE_WC_ALL_SECURED:
                      aceResources.append(" +");
                    break;
                  case OC_ACE_WC_ALL_PUBLIC:
                      aceResources.append(" -");
                    break;
                  default:
                    break;
                  }
                }
                res = res.getNext();
              }
              System.out.println(aceResources);
              ac = ac.getNext();
              System.out.println("\n------------------------------------------------");
            }
            System.out.println("\n################################################");

            /* Freeing the ACL structure */
            OCObt.freeAcl(acl);
          } else {
            System.out.println("\nERROR RETRIEVING /oic/sec/acl2");
          }
    }

}
