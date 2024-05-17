/*==============================================================*/
/* DBMS name:      MySQL 5.0                                    */
/* Created on:     2022/12/6 13:05:40                           */
/*==============================================================*/

drop table if exists Edge;

drop table if exists Node;

/*==============================================================*/
/* Table: Node                                                  */
/*==============================================================*/
create table Node
(
   node_addr            binary(17) not null,
   target_addr          binary(17) not null,
   opr_id               smallint unsigned not null,
   host_id              tinyint unsigned not null,
   primary key (node_addr),
   INDEX idx_node_opr_host (opr_id, host_id)
);

/*==============================================================*/
/* Table: Edge                                                  */
/*==============================================================*/
create table Edge
(
   src_addr             binary(17) not null,
   dst_addr             binary(17) not null,
   target_addr          binary(17) not null,
   hop_distance         tinyint unsigned not null,
   opr_id               smallint unsigned not null,
   host_id              tinyint unsigned not null,
   primary key (src_addr, dst_addr),
   INDEX idx_edge_opr_host (opr_id, host_id)
);

-- alter table Node add constraint FK_Relationship_6 foreign key (opr_id)
--       references Operation (opr_id) on delete cascade on update restrict;

-- alter table RTTL add constraint FK_Relationship_7 foreign key (node_addr)
--       references Node (node_addr) on delete cascade on update restrict;

-- alter table RTTL add constraint FK_Relationship_8 foreign key (opr_id)
--       references Operation (opr_id) on delete cascade on update restrict;

-- alter table Edge add constraint FK_Relationship_9 foreign key (src_addr)
--       references Node (node_addr) on delete cascade on update restrict;

-- alter table Edge add constraint FK_Relationship_10 foreign key (dst_addr)
--       references Node (node_addr) on delete cascade on update restrict;