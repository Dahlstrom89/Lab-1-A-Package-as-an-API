create table customer (
  custid   number(10)   not null,
  username varchar2(30) not null,
  password varchar2(40) not null
);

alter table customer add (
  constraint customer_pk primary key (custid));

alter table customer add (
  constraint customer_uk unique (username));

create sequence customer_seq;


create or replace function get_hash(
  p_username in varchar2,
  p_password in varchar2)
return varchar2
as
  l_salt varchar2(30) := 'customerSalt';
  l_hash varchar2(40);
begin
  select standard_hash(
           upper(p_username) || l_salt || upper(p_password), 'SHA1')
    into l_hash
    from dual;
  return l_hash;
end;
/
//Uppgift 1//
create or replace procedure add_customer(
  p_username in varchar2,
  p_password in varchar2
)

as
begin
  insert into customer (custid, username, password)
  values (
  customer_seq.nextval,
  p_username,
  get_hash(p_username, p_password)
);
end;
/
//Lägga till kund//
exec add_customer('P.Dahlström', 'Lösen123');

select* from customer;

//Uppgift 2//
create or replace function get_login(
    p_username in varchar2,
    p_password in varchar2
)
return number
as
    l_count number;
begin
    select count(*)
    into l_count
    from customer
    where username = p_username
      and password = get_hash(p_username, p_password);

    return l_count;
end;
/
 
 select get_login('pdahlström', 'hemligt123')
from dual;


//Uppgift 3//
create or replace procedure change_password(
  p_username in varchar2,
  p_old_password in varchar2,
  p_new_password in varchar2
)

as 
begin
  if get_login(p_username, p_old_password) = 1 then
    
	update customer
	set password = get_hash(p_username, p_new_password)
	where username = p_username;
	
	end if;
end;
/

//Utförande//
exec change_password('pdahlström', 'hemligt123', 'hemligt321');
Kontrollera med select get_login. 


//Uppgift 4//


create or replace package customer_security
as
  
  procedure add_customer(
    p_username in varchar2,
	p_password in varchar2
  );
  
  function get_login(
    p_username in varchar2,
	p_password in varchar2
  ) return number;
  
  procedure change_password(
    p_username in varchar2,
	p_old_password in varchar2,
	p_new_password in varchar2
  );
  
  procedure delete_customer(
    p_username in varchar2,
    p_password in varchar2
);
  
end customer_security;
/

//Body//

create or replace package body customer_security
as

  function get_hash(
    p_username in varchar2,
    p_password in varchar2
  )
  return varchar2
  as
    l_salt varchar2(30) := 'customerSalt';
    l_hash varchar2(40);
  begin
    select standard_hash(
      upper(p_username) || l_salt || upper(p_password),
      'SHA1'
    )
    into l_hash
    from dual;

    return l_hash;
  end;


  procedure add_customer(
    p_username in varchar2,
    p_password in varchar2
  )
  as
    l_hash varchar2(40);
  begin
    l_hash := get_hash(p_username, p_password);

    insert into customer (custid, username, password)
    values (
      customer_seq.nextval,
      p_username,
      l_hash
    );
  end;


  function get_login(
    p_username in varchar2,
    p_password in varchar2
  )
  return number
  as
    l_count number;
    l_hash  varchar2(40);
  begin
    l_hash := get_hash(p_username, p_password);

    select count(*)
    into l_count
    from customer
    where username = p_username
      and password = l_hash;

    return l_count;
  end;


  procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2,
    p_new_password in varchar2
  )
  as
    l_new_hash varchar2(40);
  begin
    if get_login(p_username, p_old_password) = 1 then

      l_new_hash := get_hash(p_username, p_new_password);

      update customer
      set password = l_new_hash
      where username = p_username;

    end if;
  end;
  


  procedure delete_customer(
    p_username in varchar2,
    p_password in varchar2
)
as
begin

    if get_login(p_username, p_password) = 1 then

        delete from customer
        where username = p_username;

    end if;

end delete_customer;

end customer_security;
/

drop function get_hash;


//Uppgift 5//

//1//
- upper är fel
- SHA1 dålig
- salt inte slumpmässisgt 
- peppar fin ej
//2//
salt lägger till en extra så att lösenords hashet blir svårae att attakera
//3//

X-26^längd av lösenord