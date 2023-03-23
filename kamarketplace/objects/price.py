from sqlalchemy import create_engine, Column, Integer, DateTime, VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

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
class PriceTable(Base):
    __tablename__ = "prod_resource_prices"

    id = Column(Integer, primary_key=True)

    column1 = Column(VARCHAR)
    column2 = Column(Integer)
    column3 = Column(Integer)
    column4 = Column(Integer)
    column5 = Column(DateTime)


class Price:
    def __init__(self, packet_content, datetime):
        self.packet_content = packet_content
        self.datetime = datetime
        self.price_1 = None
        self.price_10 = None
        self.price_100 = None
        self.object_id = self.packet_content['objectGID']
        self.id_ = "_".join([self.object_id, self.datetime])

    def to_table_format(self):
        self.price_1, self.price_10, self.price_100 = self.packet_content['prices']

    def to_pg(self):
        self.to_table_format()

        # Create a session and insert a row
        session = Session()
        row = PriceTable(id=self.id_,
                         column1=self.object_id,
                         column2=self.price_1,
                         column3=self.price_10,
                         column4=self.price_100,
                         column5=self.datetime)
        session.add(row)
        session.commit()
        session.close()

