"""Add verification and badge system models

Revision ID: f8ef57b9a486
Revises: 1ec56cb0af11
Create Date: 2025-06-07 04:19:33.162297

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f8ef57b9a486'
down_revision = '1ec56cb0af11'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('checkins',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('photo_filename', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('proof_uploads',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('upload_date', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('votes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('target_user_id', sa.Integer(), nullable=False),
    sa.Column('voter_id', sa.Integer(), nullable=False),
    sa.Column('vote_type', sa.String(length=10), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['target_user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['voter_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('media', schema=None) as batch_op:
        batch_op.add_column(sa.Column('media_type', sa.String(length=50), nullable=True))

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('checkin_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('proof_upload_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('community_votes_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('trust_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('trust_level', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('badge', sa.String(length=50), nullable=True))
        batch_op.drop_column('proof_file')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('proof_file', sa.VARCHAR(length=255), nullable=True))
        batch_op.drop_column('badge')
        batch_op.drop_column('trust_level')
        batch_op.drop_column('trust_score')
        batch_op.drop_column('community_votes_count')
        batch_op.drop_column('proof_upload_count')
        batch_op.drop_column('checkin_count')

    with op.batch_alter_table('media', schema=None) as batch_op:
        batch_op.drop_column('media_type')

    op.drop_table('votes')
    op.drop_table('proof_uploads')
    op.drop_table('checkins')
    # ### end Alembic commands ###
