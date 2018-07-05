import datetime
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class DogTypes(Base):
    __tablename__ = 'dogtypes'
    id = Column(Integer, primary_key=True)
    type = Column(String(50))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'type': self.type
            }


class DogBreeds(Base):
    __tablename__ = 'dogbreeds'
    id = Column(Integer, primary_key=True)
    name = Column(String(49))
    type = relationship(DogTypes)
    type_id = Column(Integer, ForeignKey('dogtypes.id'))
    country = Column(String(31))
    url = Column(String(90))
    image = Column(String(58))
    description = Column(String(350))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    datetime = Column(Integer, default=datetime.datetime.now)
    dogtypes = relationship(
        DogTypes, backref=backref("children", cascade="all,delete"))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type.type,
            'type_id': self.type_id,
            'country': self.country,
            'url': self.url,
            'image': self.image,
            'description': self.description
            }


engine = create_engine('sqlite:///dogbreeds.sqlite')


Base.metadata.create_all(engine)
