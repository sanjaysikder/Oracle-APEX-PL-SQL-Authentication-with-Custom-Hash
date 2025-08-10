
# Oracle APEX / PL/SQL: Authentication with Custom Hash

This guide demonstrates how to implement authentication in Oracle APEX (or any PL/SQL application) using a **custom hash function** for password storage and validation.

---

## 1. Create Custom Hash Function

```sql
CREATE OR REPLACE FUNCTION CUSTOM_HASH (
    p_userName IN VARCHAR2,
    p_password IN VARCHAR2
) RETURN VARCHAR2 IS
    l_password VARCHAR2(4000);
    l_salt     VARCHAR2(4000) := 'XV1MH24EC1IHDCQHSS6XQ6QTJSANT3';
BEGIN
    l_password := UTL_RAW.CAST_TO_RAW(
        DBMS_OBFUSCATION_TOOLKIT.MD5(
            input_string => p_password || SUBSTR(l_salt, 10, 13) ||
                            p_userName || SUBSTR(l_salt, 4, 10)
        )
    );
    RETURN l_password;
END;

```

# 2. Create a Trigger for Password Hashing

```trigger
CREATE OR REPLACE TRIGGER USER_PASSWORD_HASH
BEFORE INSERT OR UPDATE OF PASSWORD
ON MFA_USERS
REFERENCING NEW AS New OLD AS Old
FOR EACH ROW
DECLARE
BEGIN
    :NEW.PASSWORD := CUSTOM_HASH(:NEW.EMAIL, :NEW.PASSWORD);
EXCEPTION
    WHEN OTHERS THEN
        -- Consider logging the error and then re-raise
        RAISE;
END;
/
````

# 3. Create Authentication Function

```Authentication Function

CREATE OR REPLACE FUNCTION CUSTOM_AUTH (
    p_username IN VARCHAR2,
    p_password IN VARCHAR2
) RETURN BOOLEAN IS
    l_password         VARCHAR2(4000);
    l_stored_password  VARCHAR2(4000);
    l_count            NUMBER;
BEGIN
    -- First, check to see if the user exists
    SELECT COUNT(*)
      INTO l_count
      FROM MFA_USERS
     WHERE EMAIL = p_username;

    IF l_count > 0 THEN
        -- Fetch the stored hashed password
        SELECT PASSWORD
          INTO l_stored_password
          FROM MFA_USERS
         WHERE EMAIL = p_username;

        -- Apply the custom hash function to the input password
        l_password := CUSTOM_HASH(p_username, p_password);

        -- Compare hashed values
        IF l_password = l_stored_password THEN
            RETURN TRUE;
        ELSE
            RETURN FALSE;
        END IF;
    ELSE
        -- User does not exist
        RETURN FALSE;
    END IF;
END;
/
```

# 4. Test Authentication Function

```Test Authentication
DECLARE
    v_result BOOLEAN;
BEGIN
    v_result := CUSTOM_AUTH('sanjaysikder71@mail.com', 'sanjaysikder71@mail.com');
    IF v_result THEN
        DBMS_OUTPUT.PUT_LINE('Authentication successful');
    ELSE
        DBMS_OUTPUT.PUT_LINE('Authentication failed');
    END IF;
END;
/
```


# Thank You
## Sanjay Sikder
