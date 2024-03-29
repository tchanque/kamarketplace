from sqlalchemy import create_engine, Column, Integer, VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime
from kamarketplace.variables.sql import DICT_SQL_TABLES_PROD, DICT_SQL_TABLES_DEV

PG_USER = os.environ['POSTGRESQL_USER']
PG_PASSWORD = os.environ['POSTGRESQL_PWD']
PG_HOSTNAME = 'localhost'
PG_TABLE_NAME = 'postgres'

# Create an engine to connect to the database
engine = create_engine("postgresql://{}:{}@{}/{}".format(PG_USER, PG_PASSWORD, PG_HOSTNAME, PG_TABLE_NAME))

# Create a sessionmaker to create sessions with the database
Session = sessionmaker(bind=engine)

# Create a base class for declarative models
Base = declarative_base()


# Define a model for the table
class PriceTable(Base, dev=True):
    __tablename__ = DICT_SQL_TABLES_PROD

    if dev:
        __tablename__ = DICT_SQL_TABLES_DEV

    id = Column(VARCHAR, primary_key=True)

    resource_id = Column(Integer)
    price_1 = Column(Integer)
    price_10 = Column(Integer)
    price_100 = Column(Integer)
    value_date = Column(VARCHAR)


class Price:
    def __init__(self, packet_content, timestamp_):
        self.packet_content = packet_content
        self.datetime_ = datetime.fromtimestamp(timestamp_).strftime("%Y-%m-%d %H:%M:%S")
        self.price_1, self.price_10, self.price_100 = self.packet_content['prices']
        self.object_id = self.packet_content['objectGID']
        self.id_ = "_".join([str(self.object_id), str(self.datetime_)])

    def to_pg(self):

        # Create a session and insert a row
        session = Session()
        row = PriceTable(id=self.id_,
                         resource_id=self.object_id,
                         price_1=self.price_1,
                         price_10=self.price_10,
                         price_100=self.price_100,
                         value_date=self.datetime_)
        print("Inserting the rows corresponding to %s" % [self.object_id, self.price_1, self.price_10,
                                                          self.price_100, self.datetime_])
        session.add(row)
        session.commit()
        session.close()

